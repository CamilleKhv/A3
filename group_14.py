## ElGamal Digital Signature Scheme:
##===========================================================================================
# Prerequisite Package:
# pip install pycryptodome
#============================================================================================
import random 
import hashlib
from Crypto.Util.number import getPrime
import secrets
import math
#============================================================================================
def generate_large_prime(bits=256):
    return getPrime(bits)

def generate_keys():
    p = generate_large_prime()  
    g = random.randint(2, p - 2)  
    x = random.randint(2, p - 2)  
    
    y = pow(g, x, p)
    return (p, g, y), x  

# Task 1: Preventing Collision Attacks on Hash Functions
# Snippet:
def hash_message(message, salt):
    #Securely hashes the message using SHA-256 with an additional salt
    return int(hashlib.sha256((str(message) + str(salt)).encode()).hexdigest(), 16)

# Task 2: The Necessity of Hashing the Message
# Snippet:
def sign_message(message, private_key, public_key):
    p, g, y = public_key
    x = private_key
    
    h = hash_message(message, p)  

# Task 3: Improving 'k' Selection for Signature Generation
# Snippet:
    while True:
         #Generates a true random k with secrets.randbelow()
        k = secrets.randbelow(p - 2) + 1  # Ensures 1 < k < p - 1
        if math.gcd(k, p - 1) == 1:  
            break
        
    a = pow(g, k, p) 
    k_inv = pow(k, -1, p - 1)  
    b = (k_inv * (h - x * a)) % (p - 1) 

# Task 4: Attaching the Message to the Signature
# Snippet:
    #returns the message and the signature
    return {"message": message, "signature": (a, b)}

def verify_signature(message, signature, public_key):
    p, g, y = public_key
    
    #Ensure correct extraction of signature values
    a, b = signature["signature"] 

# Task 5: Ensuring Signature Validity Check in verify_signature()
# Snippet:
    
    #Verify the signature ensure 'a' is valid
    if not (1 < a < p):  
        return False
    #Verify the signature ensure 'a' is valid
    if not (0 <= b < p - 1):  
        return False

    h = hash_message(message, p) 
    
    v1 = pow(g, h, p)  
    v2 = (pow(y, a, p) * pow(a, b, p)) % p 

    return v1 == v2  

#============================================================================================
# Main Execution
if __name__ == "__main__":
    print("Generating Secure ElGamal Keys...")
    public_key, private_key = generate_keys()
    print("Keys Generated!")
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    message = input("Enter a Message to Sign:")

    signature = sign_message(message, private_key, public_key)
    print(f"Signature (a, b): {signature}")

    is_valid = verify_signature(message, signature, public_key)
    print("Signature Valid?", is_valid)

    tampered_message = input("Enter a modified message for testing tampering: ")
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print("Signature Valid on Modified Message?", is_valid_tampered)
