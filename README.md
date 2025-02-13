RSA forgery signature attack based on the bleichenbacher algorithm 
===========

PROJECT OVERVIEW 
-------------------------
This project is a proof-of-concept of the forgery signature attack on RSA cryptosystem. Presented by D. Bleichenbacher in 2006, I based my work also on this paper "Extending Bleichenbacher’s Forgery Attack" presented by Tetsuya Izu, Takeshi Shimoyama and Masahiko Takenaka.
**It is for educational purpose only and must not be used to perpetrate real attacks.**  
The script presented here uses the SHA256 algorithm and a public RSA exponenent e=3.

REQUIREMENTS 
-------------------------
This is a python project tested and developped on python 3.12.3.  
The project has no depedencies apart from smodules which are already included in all python environments.

USING AND IMPLEMENTATION DETAILS 
-------------------------
There is only one script named RSA_signature.py.  
The script generate random messages until on fits the need and then generate the signature of this message in decimal format, hexadecimal format and base64.  
You only have to modify on argument for the script to works as you wait : the size of the RSA modulus you want to use. This variable is s_n and is present at the line 63.  
Different tests are done once you put you parameter to see if it fits the conditions for the attack to work.

Then you can run the script : ``` python RSA_signature.py```  
The printed output is normally the message and the signature you are looking for !  


IN DEPTH MATHEMATICAL EXPLANATION
-------------------------
To be completed. But just refer to the document mentionned above : "Extending Bleichenbacher’s Forgery Attack" by Tetsuya Izu, Takeshi Shimoyama and Masahiko Takenaka. 

AUTHOR 
-------------------------

Antoine CHAPEL # RSA forgery attack
