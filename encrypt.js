


 function encryptData(userData,userKey){

         var encryptUserData=null;

        
               
               encryptUserData =  CryptoJS.AES.encrypt(userData,userKey);    
              
              
               encryptUserData =  encryptUserData.toString() ;
               
           
     
     return encryptUserData; 
 }
 