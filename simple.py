import numpy as np
def char_to_int(c):
    return ord(c.upper())-ord('A')
def int_to_char(n):
    return chr(n%26+ord('A'))

def ceaser_cypher(input):
    output = ""
    for i in range(len(input)):
        if input[i] == " ":
            output += " "
        elif input[i].isupper():
            output += chr((ord(input[i]) + 3 - 65) % 26 + 65)
        else:
            output += chr((ord(input[i]) + 3 - 97) % 26 + 97)
    return output

def hill_encrypt(p_text,key_matrix):
    p_text=p_text.upper().replace(" ","")
    if len(p_text)%2!=0:
        p_text+='X'
    encrypted_text=""
    for i in range(0,len(p_text),2):
        pair=[char_to_int(p_text[i]),char_to_int(p_text[i+1])]
        result=np.dot(key_matrix,pair)%26
        encrypted_text+=int_to_char(result[0])+int_to_char(result[1])
    return encrypted_text

#-------------------------------------------------------------------playfair#
def generate_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used_chars = set()
    
    for char in key:
        if char not in used_chars and char.isalpha():
            matrix.append(char)
            used_chars.add(char)
    
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    print('Matrix:')
    intial=0
    for i in range(5):
        for j in range(5):
            print(matrix[intial],end=" ")
            intial+=1
        print()
    print()

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def prepare_text(text):
    text = text.upper().replace("J", "I")
    prepared_text = ""
    
    i = 0
    while i < len(text):
        char1 = text[i]
        char2 = text[i+1] if i+1 < len(text) else 'X'
        
        if char1 == char2:
            prepared_text += char1 + 'X'
            i += 1
        else:
            prepared_text += char1 + char2
            i += 2
    
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'
    
    return prepared_text

def encrypt_pair(pair, matrix):
    row1, col1 = find_position(matrix, pair[0])
    row2, col2 = find_position(matrix, pair[1])
    
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def playfair_encrypt(text, key):
    matrix = generate_matrix(key)
    prepared_text = prepare_text(text)
    
    encrypted_text = ""
    for i in range(0, len(prepared_text), 2):
        encrypted_text += encrypt_pair(prepared_text[i:i+2], matrix)
    
    return encrypted_text

#-------------------------------------------------------------------vigener#
def generate_key(text,key):
    key=key.upper()
    if len(text)==len(key):
        return key
    else:
        key=(key*(len(text)//len(key)))+key[:len(text)%len(key)]
    return key
def vigenere_encrypt(text,key):
    text=text.upper().replace(" ","")
    key=generate_key(text,key)
    ans_text=""
    for i in range(len(text)):
        ans_text+=chr(((ord(text[i])+ord(key[i]))%26)+65)
    return ans_text


#-------------------------------------------------------------------Railfence#


def row_column_encrypt(text, rows, cols):
    grid = [['X' for _ in range(cols)] for _ in range(rows)]  
    k = 0
    
    for i in range(rows):
        for j in range(cols):
            if k < len(text):
                grid[i][j] = text[k]
                k += 1
            else:
                grid[i][j] = 'X'  
    encrypted = ""
    for j in range(cols):
        for i in range(rows):
            encrypted += grid[i][j]

    return encrypted

def row_column_decrypt(text, rows, cols):
    grid = [['' for _ in range(cols)] for _ in range(rows)]
    k = 0
    for j in range(cols):
        for i in range(rows):
            grid[i][j] = text[k]
            k += 1

    decrypted = ""
    for i in range(rows):
        for j in range(cols):
            decrypted += grid[i][j]

    return decrypted

#-------------------------------------------------------------------RowColumnCipher#

def create_matrix(text, key):
    rows, cols = len(key), len(text) // len(key) + (len(text) % len(key) != 0)
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    k = 0
    for i in range(cols):
        for j in range(rows):
            if k < len(text):
                matrix[j][i] = text[k]
                k += 1
    return matrix

def encrypt(text, key):
    matrix = create_matrix(text, key)
    sorted_key = sorted(list(key))
    encrypted_text = ''
    for k in sorted_key:
        col = key.index(k)
        for row in matrix:
            if row[col] != '':
                encrypted_text += row[col]
    return encrypted_text

def decrypt(encrypted_text, key):
    rows, cols = len(key), len(encrypted_text) // len(key) + (len(encrypted_text) % len(key) != 0)
    matrix = [['' for _ in range(cols)] for _ in range(rows)]
    sorted_key = sorted(list(key))
    k = 0
    for k_char in sorted_key:
        col = key.index(k_char)
        for row in range(rows):
            if k < len(encrypted_text):
                matrix[row][col] = encrypted_text[k]
                k += 1
    decrypted_text = ''
    for i in range(cols):
        for j in range(rows):
            if matrix[j][i] != '':
                decrypted_text += matrix[j][i]
    return decrypted_text

if __name__ == "__main__":
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
    key = input("Enter the key: ")
    text = input("Enter the text: ")

    if choice == 'e':
        encrypted = encrypt(text, key)
        print(f"Encrypted text: {encrypted}")
    elif choice == 'd':
        decrypted = decrypt(text, key)
        print(f"Decrypted text: {decrypted}")
    else:
        print("Invalid choice")

#-------------------------------------------------------------------RSA#

import random
from sympy import isprime, mod_inverse

def generate_keypair(p, q):
    if not (isprime(p) and isprime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    
    n = p * q
    phi = (p-1) * (q-1)
    
    e = random.randrange(1, phi)
    
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def encrypt(pk, plaintext):
    key, n = pk
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

if __name__ == '__main__':
    p = 61
    q = 53
    public, private = generate_keypair(p, q)
    print("Public Key: ", public)
    print("Private Key: ", private)
    
    message = "Hello"
    encrypted_msg = encrypt(public, message)
    print("Encrypted Message: ", encrypted_msg)
    
    decrypted_msg = decrypt(private, encrypted_msg)
    print("Decrypted Message: ", decrypted_msg)


#-------------------------------------------------------------------Ecluid#GCD

def GCD(a,b):
    if b==0:
        return a
    else:
        return GCD(b,a%b)
    

def ExtendedEuclidean(a,b):
    if a==0:
        return b,0,1
    gcd,x1,y1 = ExtendedEuclidean(b%a,a)
    x = y1 - (b//a) * x1
    y = x1
    return gcd,x,y

if __name__ == "__main__":
    print(GCD(10,15))
    print(ExtendedEuclidean(10,15)[0])

#-------------------------------------------------------------------Chinese Rem

def chineseRemTheorem(a, m):
    mm = 1
    for mi in m:
        mm *= mi
    M_i = [mm // mi for mi in m]
    y_i = [modInverse(M_i[i], m[i]) for i in range(len(m))]
    x = 0
    for i in range(len(a)):
        x += a[i] * M_i[i] * y_i[i]
    return x % mm, mm

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x += m0
    return x


print(chineseRemTheorem([2, 3, 2], [3, 5, 7])) 

#-------------------------------------------------------------------DES

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def des_encrypt(plain_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plain_text.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text


def des_decrypt(cipher_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return decrypted_text.decode()


def main():
    print("\nDES Encryption and Decryption")
    key = get_random_bytes(8)
    print(f"\nGenerated Key (in hexadecimal): {key.hex()}")
    
    plain_text = input("Enter the plain text to encrypt: ")
    encrypted_text = des_encrypt(plain_text, key)

    print(f"\nEncrypted Text (in hexadecimal): {encrypted_text.hex()}")
    decrypted_text = des_decrypt(encrypted_text, key)
    print(f"\nDecrypted Text: {decrypted_text}")
    

main()


#-------------------------------------------------------------------AES

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv, encrypted_text


def aes_decrypt(iv, cipher_text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    #print all
    decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_text.decode()


def main():
    print("\nAES Encryption and Decryption")
    
    key_input = input("Enter a 32-byte key (in hexadecimal): ")
    key = bytes.fromhex(key_input)
    choice = int(input("Enter choice: 1. Encrypt 2. Decrypt"))
    print()
    
    if choice == 1:
        plain_text = input("\nEnter the plain text to encrypt: ")
        iv, encrypted_text = aes_encrypt(plain_text, key)
        print(f"\nInitialization Vector (IV) (in hexadecimal): {iv.hex()}")
        print(f"\nEncrypted Text (in hexadecimal): {encrypted_text.hex()}")
    
    else:
        iv = bytes.fromhex(input("Enter IV: "))
        encrypted_text = bytes.fromhex(input("Enter Encrypted Text: "))
        decrypted_text = aes_decrypt(iv, encrypted_text, key)
        print(f"\nDecrypted Text: {decrypted_text}")

    decrypted_text = aes_decrypt(iv, encrypted_text, key)
    print(f"\nDecrypted Text: {decrypted_text}")


main()


# ECB (Electronic Codebook):
# Each block of plaintext is encrypted independently.
# Weakness: Identical plaintext blocks produce identical ciphertext blocks, making it vulnerable to pattern recognition.
# Not recommended for secure communication.



# CBC (Cipher Block Chaining):
# Each plaintext block is XORed with the previous ciphertext block before being encrypted.
# Requires an Initialization Vector (IV) for the first block to ensure that identical plaintexts produce different ciphertexts.
# More secure than ECB, as it introduces randomness with the IV and makes patterns less recognizable.
# The mode used in your code.


# CFB (Cipher Feedback):
# Converts a block cipher into a self-synchronizing stream cipher.
# Useful for encrypting data of unknown or variable length.


# OFB (Output Feedback):
# Also converts a block cipher into a stream cipher, but in a simpler way than CFB.
# Errors in transmission do not propagate, unlike in CBC.


# CTR (Counter):
# Works like a stream cipher.
# Each block of plaintext is XORed with an encrypted counter value.
# The counter increases for each subsequent block.


# GCM (Galois/Counter Mode):
# Provides both encryption and integrity/authentication.
# Often used in secure communication protocols like TLS.


#-------------------------------------------------------------------AES
