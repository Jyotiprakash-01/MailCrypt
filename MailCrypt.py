import random
import math
from Crypto.Cipher import DES
import binascii


class RSAKeyPair:
    def __init__(self):
        self.__p = self.__generate_prime()
        self.__q = self.__generate_prime()
        while self.__q == self.__p:
            self.__q = self.__generate_prime()
        self.__n = self.__p * self.__q
        self.__phi_n = (self.__p - 1) * (self.__q - 1)
        self.__e, self.__d = self.__compute_keys()

    def __generate_prime(self):
        primes = [101, 103, 107, 109, 113, 127, 131, 137, 139, 149]
        return random.choice(primes)

    def __compute_keys(self):
        while True:
            e = random.randint(2, self.__phi_n - 1)
            if math.gcd(e, self.__phi_n) == 1:
                break
        for i in range(1, self.__phi_n):
            if (e * i) % self.__phi_n == 1:
                d = i
                return e, d

    def get_public_key(self):
        return self.__e, self.__n

    def get_private_key(self):
        return self.__d


class Sender:
    def __init__(self, rsa_keypair):
        self.rsa_keypair = rsa_keypair

    def pad_message(self, msg):
        while len(msg) % 8 != 0:
            msg += " "
        return msg

    def des_encrypt(self, message, key):
        key = key.encode()
        message = self.pad_message(message).encode()
        cipher = DES.new(key, DES.MODE_ECB)
        ciphertext = cipher.encrypt(message)
        return binascii.hexlify(ciphertext).decode()

    def encrypt_key_with_rsa(self, key):
        e, n = self.rsa_keypair.get_public_key()
        return [pow(ord(char), e, n) for char in key]

    def sign_message(self, message):
        d = self.rsa_keypair.get_private_key()
        n = self.rsa_keypair.get_public_key()[1]
        return [pow(ord(char), d, n) for char in message]

    def send_message(self):
        print("\n Sender Side")
        key = input("Enter 8-character DES key: ")
        while len(key) != 8:
            key = input("Key must be exactly 8 characters. Try again: ")
        plaintext = input("Enter plaintext: ")
        print(f"\nPlaintext: {plaintext}")

        ciphertext = self.des_encrypt(plaintext, key)
        print(f"DES Ciphertext: {ciphertext}")

        encrypted_key = self.encrypt_key_with_rsa(key)
        print(f"RSA Encrypted DES Key: {encrypted_key}")

        signature = self.sign_message(plaintext)
        print(f"Digital Signature: {signature}\n")

        return ciphertext, encrypted_key, signature


class Receiver:
    def __init__(self, rsa_keypair):
        self.rsa_keypair = rsa_keypair

    def des_decrypt(self, ciphertext, key):
        ciphertext = binascii.unhexlify(ciphertext)
        key = key.encode()
        cipher = DES.new(key, DES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode().strip()

    def decrypt_key_with_rsa(self, encrypted_key):
        d = self.rsa_keypair.get_private_key()
        n = self.rsa_keypair.get_public_key()[1]
        decrypted_key = ""
        for c in encrypted_key:
            m = pow(c, d, n)
            decrypted_key += chr(m)
        return decrypted_key

    def verify_signature(self, signature, original_message):
        e, n = self.rsa_keypair.get_public_key()
        decrypted_chars = [chr(pow(s, e, n)) for s in signature]
        decrypted_message = "".join(decrypted_chars).strip()
        return decrypted_message == original_message

    def receive_message(self, ciphertext, encrypted_key, signature):
        print(" Receiver Side:")
        d = self.rsa_keypair.get_private_key()
        print(f"Private Key (d): {d}")

        decrypted_key = self.decrypt_key_with_rsa(encrypted_key)
        print(f"Decrypted DES Key: {decrypted_key}")

        plaintext = self.des_decrypt(ciphertext, decrypted_key)
        print(f"Recovered Plaintext: {plaintext}")

        if self.verify_signature(signature, plaintext):
            print(" Signature Verified: Message is authentic.")
        else:
            print(" Signature Verification Failed: Message may be tampered.")


# Main
if __name__ == "__main__":
    rsa = RSAKeyPair()
    e, n = rsa.get_public_key()
    #print(f"Public Key (e, n): ({e}, {n})")

    sender = Sender(rsa)
    ciphertext, encrypted_key, signature = sender.send_message() 

    receiver = Receiver(rsa)
    receiver.receive_message(ciphertext, encrypted_key, signature)
