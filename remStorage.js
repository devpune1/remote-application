(

function() {

  var inputElement;
  var formElement;
  var ulElement;
  var drinkRowPrefix = 'drinkrow-';

  function prefixId(id) {
    
    return drinkRowPrefix + id;
    
  }
  function unprefixId(prefixedId) {
  
    return prefixedId.replace(drinkRowPrefix, '');
    
  }

  function init() {
    
    formElement = document.getElementById('add-drink');
    inputElement = formElement.getElementsByTagName('input')[0];
    ulElement = document.getElementById('drink-list');

	console.log(inputElement);

    // Enable change events for changes in the same browser window
    RemoteStorage.config.changeEvents.window = true;

    // Claim read/write access for the /myfavoritedrinks category
    remoteStorage.access.claim('myfavoritedrinks', 'rw');

    // Display the RS connect widget
    remoteStorage.displayWidget();

    remoteStorage.myfavoritedrinks.init();

    remoteStorage.myfavoritedrinks.on('change', function(event) {
      
      if(event.newValue && (! event.oldValue)) {
        
        console.log('Change from '+event.origin+' (add)', event);
        
        displayDrink(event.relativePath, event.newValue.name);
        
      }
      else if((! event.newValue) && event.oldValue) {
        
        console.log('Change from '+event.origin+' (remove)', event);
        undisplayDrink(event.relativePath);
      }
      else if(event.newValue && event.oldValue) {
        console.log('Change from '+event.origin+' (change)', event);
        // TODO update drink
      }
    });

    remoteStorage.on('ready', function() {
      ulElement.addEventListener('click', function(event) {
        if(event.target.tagName === 'SPAN') {
          console.log(unprefixId(event.target.parentNode.id))
          removeDrink(unprefixId(event.target.parentNode.id));
        }
      });

      formElement.addEventListener('submit', function(event) {
        event.preventDefault();
        var trimmedText = inputElement.value.trim();
        if(trimmedText) {
          addDrink(trimmedText);
          addData(trimmedText);
        }
        inputElement.value = '';
      });
    });

    remoteStorage.on('disconnected', function() {
      emptyDrinks();
    });
  }

  function addDrink(name) {
    remoteStorage.myfavoritedrinks.addDrink(name);
  }

  function removeDrink(id) {
    console.log(id)
    remoteStorage.myfavoritedrinks.removeDrink(id);
  }

  function displayDrinks(drinks) {
   
    for(var drinkId in drinks) {
      
      displayDrink(drinkId, drinks[drinkId].name);
      
    }
  }

  function displayDrink(id, name) {
    
    var domID = prefixId(id);
    
    var liElement = document.getElementById(domID);
    
    if(! liElement) {
      
      liElement = document.createElement('li');
      
      liElement.id = domID;
      
      ulElement.appendChild(liElement);
      
    }
    
    liElement.appendChild(document.createTextNode(name));//this will do some html escaping
    liElement.innerHTML += ' <span title="Delete">×</span>';
  }

  function undisplayDrink(id) {
    console.log(prefixId(id))
    var elem = document.getElementById(prefixId(id));
    ulElement.removeChild(elem);
  }

  function emptyDrinks() {
    ulElement.innerHTML = '';
    inputElement.value = '';
  }

  document.addEventListener('DOMContentLoaded', init);

})();
