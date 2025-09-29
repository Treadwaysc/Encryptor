from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def generate_keys():
    """
    Generate RSA private and public keys and save them to files.
    Security+: RSA uses asymmetric encryption, where the private key is secret
    and the public key can be shared. Key size (e.g., 2048 bits) affects security.
    
    TODO:
    - Generate a 2048-bit RSA private key with public exponent 65537.
    - Derive the public key from the private key.
    - Save the private key to 'private_key.pem' in PEM format, no encryption.
    - Save the public key to 'public_key.pem' in PEM format.
    - Handle errors (e.g., file write issues) and print a success message.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()

    pem1 = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    pem1.splitlines()[0]

    pem2 = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem2.splitlines()[0]
    try:
        file1 = open("Encryption\public_key.pem", "wb")
        file2 = open("Encryption\private_key.pem", "wb")

        file1.write(pem1)
        file2.write(pem2)

        file1.close()
        file2.close()
        return "Keys successfully generated"
    except Exception as e:
        return e

def load_public_key():
    """
    Load the public key from 'public_key.pem'.
    Security+: The public key is used for encryption and can be shared freely.
    TODO:
    - Open and read 'public_key.pem' in binary mode.
    - Use serialization to load the public key from the file content.
    - Return the public key object.
    - Handle errors (e.g., file not found) and return None if it fails.
    """
    try:
        with open('X:\Scripts\Encryption\public_key.pem', 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
            return public_key
    except Exception as e:
        print(e)
        return None
    
def load_private_key():
    """
    Load the private key from 'private_key.pem'.
    Security+: The private key is used for decryption and must be kept secure.
    
    TODO:
    - Open and read 'private_key.pem' in binary mode.
    - Use serialization to load the private key (no password for simplicity).
    - Return the private key object.
    - Handle errors (e.g., file not found) and return None if it fails.
    """
    pass

def encrypt_file(input_file, output_file):
    """
    Encrypt a file using the public key.
    Security+: RSA encryption with OAEP padding is secure for small data.
    RSA can only encrypt data smaller than the key size (~245 bytes for 2048-bit).
    
    TODO:
    - Check if the input file exists and is small enough (<245 bytes).
    - Load the public key using load_public_key().
    - Read the input file in binary mode.
    - Encrypt the data using RSA with OAEP padding (use SHA256 for MGF1 and algorithm).
    - Save the encrypted data to output_file in binary mode.
    - Handle errors (e.g., file too large, file not found) and print status.
    """
    pass

def decrypt_file(input_file, output_file):
    """
    Decrypt a file using the private key.
    Security+: Only the private key can decrypt data encrypted with the public key.
    
    TODO:
    - Load the private key using load_private_key().
    - Read the encrypted input file in binary mode.
    - Decrypt the data using RSA with OAEP padding (same settings as encryption).
    - Save the decrypted data to output_file in binary mode.
    - Handle errors (e.g., file not found, decryption failure) and print status.
    """
    pass

def main():
    """
    Main program with a menu to interact with the user.
    Security+: This simulates a real-world encryption tool, showing how keys
    and encryption are used in practice.
    
    TODO:
    - Create a loop to display a menu with options:
      1. Generate keys
      2. Encrypt a file
      3. Decrypt a file
      4. Exit
    - Get user input and call the appropriate function.
    - For encryption/decryption, prompt for input and output file names.
    - Handle invalid menu choices and provide feedback.
    """
    print(generate_keys())
    print(load_public_key())
    pass

if __name__ == "__main__":
    main()