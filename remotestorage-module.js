




RemoteStorage.defineModule('bic', function(privateClient) {
    
  privateClient.declareType('data', {
    type: 'object',
    properties: {
      userName: { type: 'string' },
       userAddress: { type: 'string' },
        userNumber: { type:'string' },
         userEmail: { type: 'string' }
    },
    required: ['userName','userAddress','userNumber','userEmail']
  });

  return {
      
    exports: {

      init: function() {
          
       privateClient.cache('');
       
      },

      on: privateClient.on,

      addUData: function(name,userData) {
          
        var name = name.toString().replace(/\s|\//g, '-');
        
       
       
        return privateClient.storeObject('data', name,userData);
        
        
      },
      
      
      editUData: function(newId,userData) {
        
       var newId = newId.toString().replace(/\s|\//g, '-');
      
         return privateClient.storeObject('data',newId,userData);
      },

      removeData: function(oldID) {
          
      oldID = oldID.toString().replace(/\s|\//g, '-');
     
      
      
          return  privateClient.remove(oldID);
      },

      listData: function() {
          
        return privateClient.getAll('');
        
      }, 
      
     
     getById: function(obj) {
       
     
     obj = obj.toString().replace(/\s|\//g, '-');
     
              return privateClient.getObject(obj);
                    
                }
      
      
      

    }
  };

});
