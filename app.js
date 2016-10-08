



(function() {


  var username,number;
  var formElement;
  var ulElement;
  var userData = {};
  
  
  
var userProperty = ['userName','userAddress','userNumber','userEmail'];

 
 

  function init() {
    
        //clearRemoteStorage();
        
        
    formElement = document.getElementById('add-drink');
    name= formElement.getElementsByTagName('input')[0];
    address = formElement.getElementsByTagName('input')[1];
    number= formElement.getElementsByTagName('input')[2];
    emailAddress = formElement.getElementsByTagName('input')[3];
     
    ulElement = document.getElementsByClassName('deleteButton');

	
      
    // Enable change events for changes in the same browser window
    RemoteStorage.config.changeEvents.window = false;

    // Claim read/write access for the /myfavoritedrinks category
    remoteStorage.access.claim('bic','rw');

    // Display the RS connect widget
    remoteStorage.displayWidget();

    remoteStorage.bic.init();


   
  remoteStorage.bic.listData().then(function(transactions){
    
		
			
			for(var id in transactions){
			  
			  
			  	
			  
			   removeDuplicate(transactions[id]);
			   
		
			}
	
		});
		

    remoteStorage.on('ready', function() {
      
      
    

      formElement.addEventListener('submit', function(event) {
        
        event.preventDefault();
        
        var trimmedText = name.value.trim();
          var trimmedAddress = address.value.trim();
            var trimmedNumber = number.value.trim();
            var trimmedEmail = emailAddress.value.trim();
          
          
        if(trimmedText) {
          
           userData =  getEncryptedObject(trimmedText,trimmedAddress,trimmedNumber,trimmedEmail);
           
           addUserData( userData.userName, userData);
           addData( userData);
            
        }
        
      name.value = '';
      number.value = '';
      address.value ='';
     emailAddress.value = '';
      
      
      });
    });

    remoteStorage.on('disconnected', function() {
      //emptyDrinks();
    });
  }








function getTextBoxId(){
    
     var userTextBoxId = ["username","userpassword","userwebsite","userhint"];
    
    
    return userTextBoxId;
}


function getData(textboxID){
    
    
     var userData = [];
   var count=0;
   var obj=null;
   var flag = null;
   var userDate;
   

  
  
  
  
  for(var items = 0; items <  textboxID.length ; items++){ 
    
    
    userData[items] = document.getElementById( textboxID[items]).value;
    
    
    
}

//userData[items++] = userDate;





return userData;




}

  function addUserData(name,userData) {
    
     remoteStorage.bic.addUData(name,userData);

  }

  function removeUserData(id) {
   
    remoteStorage.bic.removeData(id);
  }

 
 
    
  document.addEventListener('DOMContentLoaded', init);

})();


