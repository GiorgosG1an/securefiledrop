import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_file(input_path: str, output_path:str) -> bytes:
    """
    Encrypts a file using AES-GCM with a randomly generated 256-bit key.
    Reads the entire contents of the input file, encrypts it using AES-GCM with a randomly generated key and nonce,
    and writes the nonce followed by the ciphertext to the output file.

    Args:
        input_path (str): Path to the plaintext input file to be encrypted.
        output_path (str): Path where the encrypted file will be written.

    Returns:
        bytes: The randomly generated 256-bit AES key used for encryption.

    Note:
        - The function currently reads the entire file into memory, which may not be suitable for very large files.
    """
    
    with open(input_path, 'rb') as f:
        # read the full file into memory.
        plaintext = f.read() # TODO optimize for streaming large files

        aes_key = os.urandom(32) # 256-bit key
        nonce = os.urandom(12) # 96-bit for IV for GCM (standard)

        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(output_path, 'rb') as f:
        f.write(nonce + ciphertext)
        
    return aes_key

