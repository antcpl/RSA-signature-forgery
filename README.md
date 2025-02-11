Bleichenbacher Attack 
===========

PROJECT OVERVIEW 
-------------------------
This project is a proof-of-concept of the Bleichenbacher attack (or "one million requests attack") on RSA cryptosystem. I didn't used modules to compute different calcuations steps.    
**It is for educational purpose only and must not be used to perpetrate real attacks.**  
All the implementation is based on the great document : "Chosen Ciphertext Attacks Against Protocols
Based on the RSA Encryption Standard
PKCS #1" by Daniel Bleichenbacher.

REQUIREMENTS 
-------------------------
This is a python project tested and developped on python 3.12.3.  
The project has no depedencies apart from sockets which is already included in all python environments.


USING AND IMPLEMENTATION DETAILS 
-------------------------
There is only one script named bleichenbacher_attack.py.  
Here is the list of the variables you need to add in the script for it to works : 
- The domain name and the port of the oracle. These are two global variables defined at lines : 5 and 6
- e and N the public RSA components. (lines 141 and 142)
- In my case I already had a valid PKCS#1 v1.5 C0 ciphertext. Thus, you can add yours in the C0 variable at the line : 157. (There is a small test after the declaration to check if the value is correct or not)  

Then you can run the script : ``` python bleichenbacher_attack.py```  
The printed output is normally the deciphered message you are looking for !  


IN DEPTH MATHEMATICAL EXPLANATION
-------------------------
To be completed. But just refer to the document mentionned above : "Chosen Ciphertext Attacks Against Protocols
Based on the RSA Encryption Standard
PKCS #1" by Daniel Bleichenbacher

AUTHOR 
-------------------------

Antoine CHAPEL # Bleichenbacher attack
