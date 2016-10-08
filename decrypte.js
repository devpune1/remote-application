
 function decryptedData(userData,userKey){

         var decryptUserData = null;

           


            decryptUserData=  CryptoJS.AES.decrypt(userData,userKey);
              
               decryptUserData =   CryptoJS.enc.Utf8.stringify(decryptUserData);
     
         
             
     
     
     return decryptUserData; 
 }
 