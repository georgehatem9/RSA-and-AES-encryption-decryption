import string
import math
main=string.ascii_lowercase
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
# Name :- George Hatem  ID :- 19104121
def perform_RSA():
    def multiplicative_inverse(a, m):
        a=a%m;
        for x in range(1,m) :
            if((a*x)%m==1) :
                return x
        return 1
    def generate_keypair(p, q):
        n=p*q
        print("Value of n: ",n)


        phi = (p-1)*(q-1)
        print("Value of phi(n): ", phi)


        print("Enter e such that is co-prime to ", phi,": ")
        e=int(input())


        g=math.gcd(e,phi)
        while(g!=1):
            print("The number you entered is not co-prime")
            e=int(input())
            g=math.gcd(e,phi)

        print("Value of exponent(e) entered is: ", e)

        d = multiplicative_inverse(e, phi)

        return (e,n),(d,n)

    def encrypt(public_key, to_encrypt):
        key, n = public_key


        cipher=pow(to_encrypt,key)%n
        return cipher


    def decrypt(private_key, to_decrypt):
        key, n = private_key


        decrypted=pow(to_decrypt,key)%n
        return decrypted

    

    p=int(input("Enter prime p: "))
    q=int(input("Enter prime q (!=p): "))

    while(p==q):
        p=int(input("Enter prime p: "))
        q=int(input("Enter prime q (!=p): "))

    print("Prime number p: ",p)
    print("Prime number q: ",q)

    print("Generating Public/Private key-pairs!")
    public, private = generate_keypair(p, q)
    print("Your public key is (e,n) ", public)
    print("Your private key is (d,n) ", private)

    print("Do you want to encrypt or decrypt? Enter '1' for encryption or '2' for decryption: ")
    choice = input()

    if choice == '1':
        message = input("Enter the message to encrypt: ")

        message = message.replace(" ", "")
        message = message.lower()
        arr = []
        cipher_text = []
        for i in message:
            if i in main:
                arr.append(main.index(i))
        for i in arr:
            cipher_text.append(encrypt(public, i))

        print("Encrypted message (Cipher Text): ", cipher_text)
    elif choice == '2':
        cipher_text = input("Enter the message to decrypt (as a list of integers separated by spaces): ")
        cipher_text = list(map(int, cipher_text.split()))

        plain = []
        for i in cipher_text:
            plain.append(decrypt(private, i))
        plain_text = ''
        for i in plain:
            plain_text = plain_text + main[i]
        print("Decrypted message (Plain Text): ", plain_text)
    else:
        print("Invalid choice. Please enter '1' for encryption or '2' for decryption.")
def perform_AES():
    class AESCipher(object):
        def __init__(self, key):
            self.block_size = AES.block_size
            self.key = hashlib.sha256(key.encode()).digest()

        def encrypt(self, plain_text):
            plain_text = self.__pad(plain_text)
            iv = Random.new().read(self.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            encrypted_text = cipher.encrypt(plain_text.encode())
            return b64encode(iv + encrypted_text).decode("utf-8")

        def decrypt(self, encrypted_text):
            encrypted_text = b64decode(encrypted_text)
            iv = encrypted_text[:self.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
            return self.__unpad(plain_text)

        def __pad(self, plain_text):
            number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
            ascii_string = chr(number_of_bytes_to_pad)
            padding_str = number_of_bytes_to_pad * ascii_string
            padded_plain_text = plain_text + padding_str
            print("The plain text after padding: ",padded_plain_text)
            return padded_plain_text

        @staticmethod
        def __unpad(plain_text):
            last_character = plain_text[len(plain_text) - 1:]
            return plain_text[:-ord(last_character)]

    key=input("Enter the key: ")
    c=AESCipher(key)
    print("Press 1 for encryption or 2 for decryption :- ")
    option= input();
    if(option == '1'):
      plain_text=input("Enter the message: ")
      print("The message is: ", plain_text)
      cipher=c.encrypt(plain_text)
      print("Encrypted message is: ",cipher)
    else:
      print("Enter the Encrypted text :- ")
      cipher2 = input()
      dec=c.decrypt(cipher2)
      print("Decrypted message is: ",dec)

print("Hello, my name is George Hatem.")
print("Welcome to my Encryption and Decryption System.")
print("Press 1 for RSA or 2 for AES :- ")
x = input()
if x == '1':
 perform_RSA()
else:
 perform_AES()


