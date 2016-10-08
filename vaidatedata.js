











function validateUserData(userDataObject,results,userEncryptionKey,userDataProperty){
    
    var flag = 0;

   
   results = decryptAllData(results,userEncryptionKey,userDataProperty);
   
   userDataObject = decryptAllData(userDataObject,userEncryptionKey,userDataProperty);
    
    
    
    console.log( " " +results +"  "+ userDataObject);
    if(decryptAllData(userDataObject,userEncryptionKey,userDataProperty)){
        
     
       
        
    
    
    for(var items = 0; items <  userDataProperty.length ; items++){
        
        
  console.log( results[userDataProperty[items]]);
    
    console.log(userDataObject[userDataProperty[items]]);
        
            if(results[userDataProperty[items]] == userDataObject[userDataProperty[items]]){
                
                                
                        flag = 1;
                
                
                
            } 
            else {
                
                
                
                flag = 0 ;
                break ;
            }
     
        
        
    }
    
    
    }
    
else{
    
    
    flag = 0;
    
    
}

    return flag;
    
    
}

