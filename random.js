  1 /** @fileOverview Random number generator.
  2  *
  3  * @author Emily Stark
  4  * @author Mike Hamburg
  5  * @author Dan Boneh
  6  */
  7 
  8 /** @constructor
  9  * @class Random number generator
 10  * @description
 11  * <b>Use sjcl.random as a singleton for this class!</b>
 12  * <p>
 13  * This random number generator is a derivative of Ferguson and Schneier's
 14  * generator Fortuna.  It collects entropy from various events into several
 15  * pools, implemented by streaming SHA-256 instances.  It differs from
 16  * ordinary Fortuna in a few ways, though.
 17  * </p>
 18  *
 19  * <p>
 20  * Most importantly, it has an entropy estimator.  This is present because
 21  * there is a strong conflict here between making the generator available
 22  * as soon as possible, and making sure that it doesn't "run on empty".
 23  * In Fortuna, there is a saved state file, and the system is likely to have
 24  * time to warm up.
 25  * </p>
 26  *
 27  * <p>
 28  * Second, because users are unlikely to stay on the page for very long,
 29  * and to speed startup time, the number of pools increases logarithmically:
 30  * a new pool is created when the previous one is actually used for a reseed.
 31  * This gives the same asymptotic guarantees as Fortuna, but gives more
 32  * entropy to early reseeds.
 33  * </p>
 34  *
 35  * <p>
 36  * The entire mechanism here feels pretty klunky.  Furthermore, there are
 37  * several improvements that should be made, including support for
 38  * dedicated cryptographic functions that may be present in some browsers;
 39  * state files in local storage; cookies containing randomness; etc.  So
 40  * look for improvements in future versions.
 41  * </p>
 42  */
 43 sjcl.prng = function(defaultParanoia) {
 44   
 45   /* private */
 46   this._pools                   = [new sjcl.hash.sha256()];
 47   this._poolEntropy             = [0];
 48   this._reseedCount             = 0;
 49   this._robins                  = {};
 50   this._eventId                 = 0;
 51   
 52   this._collectorIds            = {};
 53   this._collectorIdNext         = 0;
 54   
 55   this._strength                = 0;
 56   this._poolStrength            = 0;
 57   this._nextReseed              = 0;
 58   this._key                     = [0,0,0,0,0,0,0,0];
 59   this._counter                 = [0,0,0,0];
 60   this._cipher                  = undefined;
 61   this._defaultParanoia         = defaultParanoia;
 62   
 63   /* event listener stuff */
 64   this._collectorsStarted       = false;
 65   this._callbacks               = {progress: {}, seeded: {}};
 66   this._callbackI               = 0;
 67   
 68   /* constants */
 69   this._NOT_READY               = 0;
 70   this._READY                   = 1;
 71   this._REQUIRES_RESEED         = 2;
 72 
 73   this._MAX_WORDS_PER_BURST     = 65536;
 74   this._PARANOIA_LEVELS         = [0,48,64,96,128,192,256,384,512,768,1024];
 75   this._MILLISECONDS_PER_RESEED = 30000;
 76   this._BITS_PER_RESEED         = 80;
 77 };
 78  
 79 sjcl.prng.prototype = {
 80   /** Generate several random words, and return them in an array.
 81    * A word consists of 32 bits (4 bytes)
 82    * @param {Number} nwords The number of words to generate.
 83    */
 84   randomWords: function (nwords, paranoia) {
 85     var out = [], i, readiness = this.isReady(paranoia), g;
 86   
 87     if (readiness === this._NOT_READY) {
 88       throw new sjcl.exception.notReady("generator isn't seeded");
 89     } else if (readiness & this._REQUIRES_RESEED) {
 90       this._reseedFromPools(!(readiness & this._READY));
 91     }
 92   
 93     for (i=0; i<nwords; i+= 4) {
 94       if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
 95         this._gate();
 96       }
 97    
 98       g = this._gen4words();
 99       out.push(g[0],g[1],g[2],g[3]);
100     }
101     this._gate();
102   
103     return out.slice(0,nwords);
104   },
105   
106   setDefaultParanoia: function (paranoia, allowZeroParanoia) {
107     if (paranoia === 0 && allowZeroParanoia !== "Setting paranoia=0 will ruin your security; use it only for testing") {
108       throw "Setting paranoia=0 will ruin your security; use it only for testing";
109     }
110 
111     this._defaultParanoia = paranoia;
112   },
113   
114   /**
115    * Add entropy to the pools.
116    * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
117    * @param {Number} estimatedEntropy The estimated entropy of data, in bits
118    * @param {String} source The source of the entropy, eg "mouse"
119    */
120   addEntropy: function (data, estimatedEntropy, source) {
121     source = source || "user";
122   
123     var id,
124       i, tmp,
125       t = (new Date()).valueOf(),
126       robin = this._robins[source],
127       oldReady = this.isReady(), err = 0, objName;
128       
129     id = this._collectorIds[source];
130     if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }
131       
132     if (robin === undefined) { robin = this._robins[source] = 0; }
133     this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;
134   
135     switch(typeof(data)) {
136       
137     case "number":
138       if (estimatedEntropy === undefined) {
139         estimatedEntropy = 1;
140       }
141       this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,1,data|0]);
142       break;
143       
144     case "object":
145       objName = Object.prototype.toString.call(data);
146       if (objName === "[object Uint32Array]") {
147         tmp = [];
148         for (i = 0; i < data.length; i++) {
149           tmp.push(data[i]);
150         }
151         data = tmp;
152       } else {
153         if (objName !== "[object Array]") {
154           err = 1;
155         }
156         for (i=0; i<data.length && !err; i++) {
157           if (typeof(data[i]) !== "number") {
158             err = 1;
159           }
160         }
161       }
162       if (!err) {
163         if (estimatedEntropy === undefined) {
164           /* horrible entropy estimator */
165           estimatedEntropy = 0;
166           for (i=0; i<data.length; i++) {
167             tmp= data[i];
168             while (tmp>0) {
169               estimatedEntropy++;
170               tmp = tmp >>> 1;
171             }
172           }
173         }
174         this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,data.length].concat(data));
175       }
176       break;
177       
178     case "string":
179       if (estimatedEntropy === undefined) {
180        /* English text has just over 1 bit per character of entropy.
181         * But this might be HTML or something, and have far less
182         * entropy than English...  Oh well, let's just say one bit.
183         */
184        estimatedEntropy = data.length;
185       }
186       this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,data.length]);
187       this._pools[robin].update(data);
188       break;
189       
190     default:
191       err=1;
192     }
193     if (err) {
194       throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
195     }
196   
197     /* record the new strength */
198     this._poolEntropy[robin] += estimatedEntropy;
199     this._poolStrength += estimatedEntropy;
200   
201     /* fire off events */
202     if (oldReady === this._NOT_READY) {
203       if (this.isReady() !== this._NOT_READY) {
204         this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
205       }
206       this._fireEvent("progress", this.getProgress());
207     }
208   },
209   
210   /** Is the generator ready? */
211   isReady: function (paranoia) {
212     var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];
213   
214     if (this._strength && this._strength >= entropyRequired) {
215       return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
216         this._REQUIRES_RESEED | this._READY :
217         this._READY;
218     } else {
219       return (this._poolStrength >= entropyRequired) ?
220         this._REQUIRES_RESEED | this._NOT_READY :
221         this._NOT_READY;
222     }
223   },
224   
225   /** Get the generator's progress toward readiness, as a fraction */
226   getProgress: function (paranoia) {
227     var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];
228   
229     if (this._strength >= entropyRequired) {
230       return 1.0;
231     } else {
232       return (this._poolStrength > entropyRequired) ?
233         1.0 :
234         this._poolStrength / entropyRequired;
235     }
236   },
237   
238   /** start the built-in entropy collectors */
239   startCollectors: function () {
240     if (this._collectorsStarted) { return; }
241   
242     if (window.addEventListener) {
243       window.addEventListener("load", this._loadTimeCollector, false);
244       window.addEventListener("mousemove", this._mouseCollector, false);
245     } else if (document.attachEvent) {
246       document.attachEvent("onload", this._loadTimeCollector);
247       document.attachEvent("onmousemove", this._mouseCollector);
248     }
249     else {
250       throw new sjcl.exception.bug("can't attach event");
251     }
252   
253     this._collectorsStarted = true;
254   },
255   
256   /** stop the built-in entropy collectors */
257   stopCollectors: function () {
258     if (!this._collectorsStarted) { return; }
259   
260     if (window.removeEventListener) {
261       window.removeEventListener("load", this._loadTimeCollector, false);
262       window.removeEventListener("mousemove", this._mouseCollector, false);
263     } else if (window.detachEvent) {
264       window.detachEvent("onload", this._loadTimeCollector);
265       window.detachEvent("onmousemove", this._mouseCollector);
266     }
267     this._collectorsStarted = false;
268   },
269   
270   /* use a cookie to store entropy.
271   useCookie: function (all_cookies) {
272       throw new sjcl.exception.bug("random: useCookie is unimplemented");
273   },*/
274   
275   /** add an event listener for progress or seeded-ness. */
276   addEventListener: function (name, callback) {
277     this._callbacks[name][this._callbackI++] = callback;
278   },
279   
280   /** remove an event listener for progress or seeded-ness */
281   removeEventListener: function (name, cb) {
282     var i, j, cbs=this._callbacks[name], jsTemp=[];
283   
284     /* I'm not sure if this is necessary; in C++, iterating over a
285      * collection and modifying it at the same time is a no-no.
286      */
287   
288     for (j in cbs) {
289       if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
290         jsTemp.push(j);
291       }
292     }
293   
294     for (i=0; i<jsTemp.length; i++) {
295       j = jsTemp[i];
296       delete cbs[j];
297     }
298   },
299   
300   /** Generate 4 random words, no reseed, no gate.
301    * @private
302    */
303   _gen4words: function () {
304     for (var i=0; i<4; i++) {
305       this._counter[i] = this._counter[i]+1 | 0;
306       if (this._counter[i]) { break; }
307     }
308     return this._cipher.encrypt(this._counter);
309   },
310   
311   /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
312    * @private
313    */
314   _gate: function () {
315     this._key = this._gen4words().concat(this._gen4words());
316     this._cipher = new sjcl.cipher.aes(this._key);
317   },
318   
319   /** Reseed the generator with the given words
320    * @private
321    */
322   _reseed: function (seedWords) {
323     this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
324     this._cipher = new sjcl.cipher.aes(this._key);
325     for (var i=0; i<4; i++) {
326       this._counter[i] = this._counter[i]+1 | 0;
327       if (this._counter[i]) { break; }
328     }
329   },
330   
331   /** reseed the data from the entropy pools
332    * @param full If set, use all the entropy pools in the reseed.
333    */
334   _reseedFromPools: function (full) {
335     var reseedData = [], strength = 0, i;
336   
337     this._nextReseed = reseedData[0] =
338       (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
339     
340     for (i=0; i<16; i++) {
341       /* On some browsers, this is cryptographically random.  So we might
342        * as well toss it in the pot and stir...
343        */
344       reseedData.push(Math.random()*0x100000000|0);
345     }
346     
347     for (i=0; i<this._pools.length; i++) {
348      reseedData = reseedData.concat(this._pools[i].finalize());
349      strength += this._poolEntropy[i];
350      this._poolEntropy[i] = 0;
351    
352      if (!full && (this._reseedCount & (1<<i))) { break; }
353     }
354   
355     /* if we used the last pool, push a new one onto the stack */
356     if (this._reseedCount >= 1 << this._pools.length) {
357      this._pools.push(new sjcl.hash.sha256());
358      this._poolEntropy.push(0);
359     }
360   
361     /* how strong was this reseed? */
362     this._poolStrength -= strength;
363     if (strength > this._strength) {
364       this._strength = strength;
365     }
366   
367     this._reseedCount ++;
368     this._reseed(reseedData);
369   },
370   
371   _mouseCollector: function (ev) {
372     var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
373     sjcl.random.addEntropy([x,y], 2, "mouse");
374     this._addCurrentTimeToEntropy(0);
375   },
376   
377   _loadTimeCollector: function () {
378     this._addCurrentTimeToEntropy(2);
379   },
380 
381   _addCurrentTimeToEntropy: function (estimatedEntropy) {
382     if (window && window.performance && typeof window.performance.now === "function") {
383       //how much entropy do we want to add here?
384       sjcl.random.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
385     } else {
386       sjcl.random.addEntropy((new Date()).valueOf(), estimatedEntropy, "loadtime");
387     }
388   },
389   
390   _fireEvent: function (name, arg) {
391     var j, cbs=sjcl.random._callbacks[name], cbsTemp=[];
392     /* TODO: there is a race condition between removing collectors and firing them */
393 
394     /* I'm not sure if this is necessary; in C++, iterating over a
395      * collection and modifying it at the same time is a no-no.
396      */
397   
398     for (j in cbs) {
399      if (cbs.hasOwnProperty(j)) {
400         cbsTemp.push(cbs[j]);
401      }
402     }
403   
404     for (j=0; j<cbsTemp.length; j++) {
405      cbsTemp[j](arg);
406     }
407   }
408 };
409 
410 /** an instance for the prng.
411 * @see sjcl.prng
412 */
413 sjcl.random = new sjcl.prng(6);
414 
415 (function(){
416   try {
417     var buf, crypt, getRandomValues, ab;
418     // get cryptographically strong entropy depending on runtime environment
419     if (typeof module !== 'undefined' && module.exports) {
420       // get entropy for node.js
421       crypt = require('crypto');
422       buf = crypt.randomBytes(1024/8);
423       sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
424 
425     } else if (window) {
426       if (window.crypto && window.crypto.getRandomValues) {
427         getRandomValues = window.crypto.getRandomValues;
428       } else if (window.msCrypto && window.msCrypto.getRandomValues) {
429         getRandomValues = window.msCrypto.getRandomValues;
430       }
431 
432       if (getRandomValues) {
433         // get cryptographically strong entropy in Webkit
434         ab = new Uint32Array(32);
435         getRandomValues(ab);
436         sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
437       }
438 
439     } else {
440       // no getRandomValues :-(
441     }
442   } catch (e) {
443     //we do not want the library to fail due to randomness not being maintained.
444   }
445 }());
446 