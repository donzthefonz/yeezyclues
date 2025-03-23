import subprocess
import tempfile
import getpass
import os
import sys
import shutil
import argparse
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, password):
    """
    Encrypts the provided data using AES-CBC with a key derived from the password.
    
    Args:
        data (bytes): The data to encrypt.
        password (str): The password for encryption.
    
    Returns:
        bytes: The encrypted data prefixed with salt and IV.
    """
    backend = default_backend()
    # Generate a random salt for key derivation
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=100000,
        backend=backend
    )
    # Derive the key from the password
    key = kdf.derive(password.encode())
    # Generate a random initialization vector
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    # Pad the data to a multiple of the block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Return salt + IV + ciphertext
    return salt + iv + ciphertext

def decrypt_data(encrypted_data, password):
    """
    Decrypts the encrypted data using AES-CBC with a key derived from the password.
    
    Args:
        encrypted_data (bytes): The encrypted data including salt and IV.
        password (str): The password for decryption.
    
    Returns:
        bytes: The decrypted data.
    """
    backend = default_backend()
    # Extract salt, IV, and ciphertext
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    # Derive the key from the password
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    # Decrypt the data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def hide_data(secret_file, image_file, output_image):
    """
    Encrypts the data from secret_file and hides it in the JPEG image.
    
    Args:
        secret_file (str): Path to the file containing data to hide.
        image_file (str): Path to the input JPEG image.
        output_image (str): Path to save the JPEG with hidden data.
    """
    # Read the secret data
    with open(secret_file, 'rb') as f:
        data = f.read()
    # Prompt for encryption password
    password = getpass.getpass("Enter encryption password: ")
    # Encrypt the data
    encrypted_data = encrypt_data(data, password)
    # Create a temporary file to store encrypted data
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(encrypted_data)
        temp_file = temp.name
    try:
        # Use steghide to embed the encrypted data into the JPEG
        subprocess.run(
            ['steghide', 'embed', '-ef', temp_file, '-cf', image_file, '-sf', output_image, '-p', ''],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"Data successfully hidden in {output_image}")
    except subprocess.CalledProcessError as e:
        print(f"Error hiding data with steghide: {e.stderr.decode()}")
        sys.exit(1)
    finally:
        # Clean up the temporary file
        os.remove(temp_file)

def extract_data(image_file, output_file):
    """
    Extracts and decrypts the hidden data from the JPEG image.
    
    Args:
        image_file (str): Path to the JPEG image with hidden data.
        output_file (str): Path to save the extracted and decrypted data.
    """
    # Create a temporary file to store extracted encrypted data
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp_file = temp.name
    try:
        # Use steghide to extract the encrypted data
        subprocess.run(
            ['steghide', 'extract', '-sf', image_file, '-xf', temp_file, '-p', ''],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Read the extracted encrypted data
        with open(temp_file, 'rb') as f:
            encrypted_data = f.read()
        # Prompt for decryption password
        password = getpass.getpass("Enter decryption password: ")
        try:
            # Decrypt the data
            data = decrypt_data(encrypted_data, password)
            # Save the decrypted data
            with open(output_file, 'wb') as f:
                f.write(data)
            print(f"Data successfully extracted to {output_file}")
        except Exception:
            print("Decryption failed. Possibly incorrect password.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error extracting data with steghide: {e.stderr.decode()}")
        sys.exit(1)
    finally:
        # Clean up the temporary file
        os.remove(temp_file)

def main():
    """Main function to handle command-line arguments and execute operations."""
    # Check if steghide is installed
    if shutil.which('steghide') is None:
        print("Error: Steghide is not installed or not in PATH.")
        sys.exit(1)

    # Set up argument parser
    parser = argparse.ArgumentParser(description="Hide or extract encrypted data in JPEG images.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Parser for 'hide' command
    hide_parser = subparsers.add_parser('hide', help='Hide data in an image')
    hide_parser.add_argument('secret_file', help='File containing the data to hide')
    hide_parser.add_argument('image_file', help='Input JPEG image')
    hide_parser.add_argument('output_image', help='Output JPEG image with hidden data')

    # Parser for 'extract' command
    extract_parser = subparsers.add_parser('extract', help='Extract data from an image')
    extract_parser.add_argument('image_file', help='JPEG image with hidden data')
    extract_parser.add_argument('output_file', help='File to save the extracted data')

    # Parse arguments
    args = parser.parse_args()

    # Execute the requested command
    if args.command == 'hide':
        hide_data(args.secret_file, args.image_file, args.output_image)
    elif args.command == 'extract':
        extract_data(args.image_file, args.output_file)

if __name__ == '__main__':
    main()