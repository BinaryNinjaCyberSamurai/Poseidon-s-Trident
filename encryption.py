from cryptography.fernet import Fernet

class Encryption:
    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt(self, data):
        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return encrypted_data

    def decrypt(self, encrypted_data):
        decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data

if __name__ == "__main__":
    # Example usage
    my_key = b"your_secret_key_here"  # Replace with your own secret key
    my_data = "Hello, world!"

    encryptor = Encryption(key=my_key)
    encrypted_message = encryptor.encrypt(my_data)
    decrypted_message = encryptor.decrypt(encrypted_message)

    print(f"Original message: {my_data}")
    print(f"Encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")
