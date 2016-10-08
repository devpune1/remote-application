  1 /** @fileOverview Convenince functions centered around JSON encapsulation.
  2  *
  3  * @author Emily Stark
  4  * @author Mike Hamburg
  5  * @author Dan Boneh
  6  */
  7  
  8  /** @namespace JSON encapsulation */
  9  sjcl.json = {
 10   /** Default values for encryption */
 11   defaults: { v:1, iter:1000, ks:128, ts:64, mode:"ccm", adata:"", cipher:"aes" },
 12 
 13   /** Simple encryption function.
 14    * @param {String|bitArray} password The password or key.
 15    * @param {String} plaintext The data to encrypt.
 16    * @param {Object} [params] The parameters including tag, iv and salt.
 17    * @param {Object} [rp] A returned version with filled-in parameters.
 18    * @return {String} The ciphertext.
 19    * @throws {sjcl.exception.invalid} if a parameter is invalid.
 20    */
 21   encrypt: function (password, plaintext, params, rp) {
 22     params = params || {};
 23     rp = rp || {};
 24     
 25     var j = sjcl.json, p = j._add({ iv: sjcl.random.randomWords(4,0) },
 26                                   j.defaults), tmp, prp, adata;
 27     j._add(p, params);
 28     adata = p.adata;
 29     if (typeof p.salt === "string") {
 30       p.salt = sjcl.codec.base64.toBits(p.salt);
 31     }
 32     if (typeof p.iv === "string") {
 33       p.iv = sjcl.codec.base64.toBits(p.iv);
 34     }
 35     
 36     if (!sjcl.mode[p.mode] ||
 37         !sjcl.cipher[p.cipher] ||
 38         (typeof password === "string" && p.iter <= 100) ||
 39         (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
 40         (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
 41         (p.iv.length < 2 || p.iv.length > 4)) {
 42       throw new sjcl.exception.invalid("json encrypt: invalid parameters");
 43     }
 44     
 45     if (typeof password === "string") {
 46       tmp = sjcl.misc.cachedPbkdf2(password, p);
 47       password = tmp.key.slice(0,p.ks/32);
 48       p.salt = tmp.salt;
 49     } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
 50       tmp = password.kem();
 51       p.kemtag = tmp.tag;
 52       password = tmp.key.slice(0,p.ks/32);
 53     }
 54     if (typeof plaintext === "string") {
 55       plaintext = sjcl.codec.utf8String.toBits(plaintext);
 56     }
 57     if (typeof adata === "string") {
 58       adata = sjcl.codec.utf8String.toBits(adata);
 59     }
 60     prp = new sjcl.cipher[p.cipher](password);
 61     
 62     /* return the json data */
 63     j._add(rp, p);
 64     rp.key = password;
 65     
 66     /* do the encryption */
 67     p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
 68     
 69     //return j.encode(j._subtract(p, j.defaults));
 70     return j.encode(p);
 71   },
 72   
 73   /** Simple decryption function.
 74    * @param {String|bitArray} password The password or key.
 75    * @param {String} ciphertext The ciphertext to decrypt.
 76    * @param {Object} [params] Additional non-default parameters.
 77    * @param {Object} [rp] A returned object with filled parameters.
 78    * @return {String} The plaintext.
 79    * @throws {sjcl.exception.invalid} if a parameter is invalid.
 80    * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
 81    */
 82   decrypt: function (password, ciphertext, params, rp) {
 83     params = params || {};
 84     rp = rp || {};
 85     
 86     var j = sjcl.json, p = j._add(j._add(j._add({},j.defaults),j.decode(ciphertext)), params, true), ct, tmp, prp, adata=p.adata;
 87     if (typeof p.salt === "string") {
 88       p.salt = sjcl.codec.base64.toBits(p.salt);
 89     }
 90     if (typeof p.iv === "string") {
 91       p.iv = sjcl.codec.base64.toBits(p.iv);
 92     }
 93     
 94     if (!sjcl.mode[p.mode] ||
 95         !sjcl.cipher[p.cipher] ||
 96         (typeof password === "string" && p.iter <= 100) ||
 97         (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
 98         (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
 99         (!p.iv) ||
100         (p.iv.length < 2 || p.iv.length > 4)) {
101       throw new sjcl.exception.invalid("json decrypt: invalid parameters");
102     }
103     
104     if (typeof password === "string") {
105       tmp = sjcl.misc.cachedPbkdf2(password, p);
106       password = tmp.key.slice(0,p.ks/32);
107       p.salt  = tmp.salt;
108     } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
109       password = password.unkem(sjcl.codec.base64.toBits(p.kemtag)).slice(0,p.ks/32);
110     }
111     if (typeof adata === "string") {
112       adata = sjcl.codec.utf8String.toBits(adata);
113     }
114     prp = new sjcl.cipher[p.cipher](password);
115     
116     /* do the decryption */
117     ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
118     
119     /* return the json data */
120     j._add(rp, p);
121     rp.key = password;
122     
123     return sjcl.codec.utf8String.fromBits(ct);
124   },
125   
126   /** Encode a flat structure into a JSON string.
127    * @param {Object} obj The structure to encode.
128    * @return {String} A JSON string.
129    * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
130    * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
131    */
132   encode: function (obj) {
133     var i, out='{', comma='';
134     for (i in obj) {
135       if (obj.hasOwnProperty(i)) {
136         if (!i.match(/^[a-z0-9]+$/i)) {
137           throw new sjcl.exception.invalid("json encode: invalid property name");
138         }
139         out += comma + '"' + i + '":';
140         comma = ',';
141         
142         switch (typeof obj[i]) {
143         case 'number':
144         case 'boolean':
145           out += obj[i];
146           break;
147           
148         case 'string':
149           out += '"' + escape(obj[i]) + '"';
150           break;
151         
152         case 'object':
153           out += '"' + sjcl.codec.base64.fromBits(obj[i],0) + '"';
154           break;
155         
156         default:
157           throw new sjcl.exception.bug("json encode: unsupported type");
158         }
159       }
160     }
161     return out+'}';
162   },
163   
164   /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
165    * adata, salt and iv will be base64-decoded.
166    * @param {String} str The string.
167    * @return {Object} The decoded structure.
168    * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
169    */
170   decode: function (str) {
171     str = str.replace(/\s/g,'');
172     if (!str.match(/^\{.*\}$/)) { 
173       throw new sjcl.exception.invalid("json decode: this isn't json!");
174     }
175     var a = str.replace(/^\{|\}$/g, '').split(/,/), out={}, i, m;
176     for (i=0; i<a.length; i++) {
177       if (!(m=a[i].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))) {
178         throw new sjcl.exception.invalid("json decode: this isn't json!");
179       }
180       if (m[3]) {
181         out[m[2]] = parseInt(m[3],10);
182       } else {
183         out[m[2]] = m[2].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(m[4]) : unescape(m[4]);
184       }
185     }
186     return out;
187   },
188   
189   /** Insert all elements of src into target, modifying and returning target.
190    * @param {Object} target The object to be modified.
191    * @param {Object} src The object to pull data from.
192    * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
193    * @return {Object} target.
194    * @private
195    */
196   _add: function (target, src, requireSame) {
197     if (target === undefined) { target = {}; }
198     if (src === undefined) { return target; }
199     var i;
200     for (i in src) {
201       if (src.hasOwnProperty(i)) {
202         if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
203           throw new sjcl.exception.invalid("required parameter overridden");
204         }
205         target[i] = src[i];
206       }
207     }
208     return target;
209   },
210   
211   /** Remove all elements of minus from plus.  Does not modify plus.
212    * @private
213    */
214   _subtract: function (plus, minus) {
215     var out = {}, i;
216     
217     for (i in plus) {
218       if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
219         out[i] = plus[i];
220       }
221     }
222     
223     return out;
224   },
225   
226   /** Return only the specified elements of src.
227    * @private
228    */
229   _filter: function (src, filter) {
230     var out = {}, i;
231     for (i=0; i<filter.length; i++) {
232       if (src[filter[i]] !== undefined) {
233         out[filter[i]] = src[filter[i]];
234       }
235     }
236     return out;
237   }
238 };
239 
240 /** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
241  * @param {String|bitArray} password The password or key.
242  * @param {String} plaintext The data to encrypt.
243  * @param {Object} [params] The parameters including tag, iv and salt.
244  * @param {Object} [rp] A returned version with filled-in parameters.
245  * @return {String} The ciphertext.
246  */
247 sjcl.encrypt = sjcl.json.encrypt;
248 
249 /** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
250  * @param {String|bitArray} password The password or key.
251  * @param {String} ciphertext The ciphertext to decrypt.
252  * @param {Object} [params] Additional non-default parameters.
253  * @param {Object} [rp] A returned object with filled parameters.
254  * @return {String} The plaintext.
255  */
256 sjcl.decrypt = sjcl.json.decrypt;
257 
258 /** The cache for cachedPbkdf2.
259  * @private
260  */
261 sjcl.misc._pbkdf2Cache = {};
262 
263 /** Cached PBKDF2 key derivation.
264  * @param {String} password The password.
265  * @param {Object} [params] The derivation params (iteration count and optional salt).
266  * @return {Object} The derived data in key, the salt in salt.
267  */
268 sjcl.misc.cachedPbkdf2 = function (password, obj) {
269   var cache = sjcl.misc._pbkdf2Cache, c, cp, str, salt, iter;
270   
271   obj = obj || {};
272   iter = obj.iter || 1000;
273   
274   /* open the cache for this password and iteration count */
275   cp = cache[password] = cache[password] || {};
276   c = cp[iter] = cp[iter] || { firstSalt: (obj.salt && obj.salt.length) ?
277                      obj.salt.slice(0) : sjcl.random.randomWords(2,0) };
278           
279   salt = (obj.salt === undefined) ? c.firstSalt : obj.salt;
280   
281   c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
282   return { key: c[salt].slice(0), salt:salt.slice(0) };
283 };
284 
285 
286 