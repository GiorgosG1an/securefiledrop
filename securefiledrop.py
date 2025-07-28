import os
import base64
import argparse

from crypto.aes import encrypt_file, decrypt_file
from crypto.hmac_signer import log_event

def upload_file(args):
    print(f"Uploading: {args.input}")
    input_path = args.input
    filename = os.path.basename(input_path)
    output_path = os.path.join("uploads", filename + ".enc")

    aes_key = encrypt_file(input_path, output_path)
    print(f"File encrypted and saved as: {output_path}")

    b64key = base64.b64encode(aes_key).decode()
    print(f"AES key (base64): {b64key}")
    log_event("upload", os.path.basename(output_path))
    print("Save this key securely to decrypt the file later.")

def download_file(args):
    print(f"Downloading: {args.input}")
    input_path = args.input
    filename = os.path.basename(input_path).replace(".enc", ".decrypted")
    output_path = os.path.join(".", filename)

    # Ask user for base64 AES key (interactive for now)
    b64key = input("🔐 Enter the AES key (base64): ").strip()
    try:
        aes_key = base64.b64decode(b64key)
        if len(aes_key) != 32:
            raise ValueError("Invalid AES key length")
    except Exception as e:
        print(f"Error decoding AES key: {e}")
        return

    try:
        decrypt_file(input_path, output_path, aes_key)
        print(f"✅ File decrypted and saved as: {output_path}")
        log_event("download", os.path.basename(input_path))
    except Exception as e:
        print(f"❌ Decryption failed: {e}")

def verify_logs(args):
    print("Verifying logs...")

def main():
    parser = argparse.ArgumentParser(description="SecureFileDrop - Encrypted File Sharing CLI.")

    subparsers = parser.add_subparsers(dest="command")

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Encrypt and upload a file")
    upload_parser.add_argument("input", help="Path to the input file")
    upload_parser.add_argument("--recipient", help="Path to recipient's RSA public key (optional)")
    upload_parser.set_defaults(func=upload_file)

    # Download command
    download_parser = subparsers.add_parser("download", help="Download and decrypt a file")
    download_parser.add_argument("input", help="Path to encrypted file")
    download_parser.add_argument("--private-key", help="Path to RSA private key (optional)")
    download_parser.set_defaults(func=download_file)

    # Verify logs
    verify_parser = subparsers.add_parser("verify-logs", help="Verify integrity of access logs")
    verify_parser.set_defaults(func=verify_logs)

    args = parser.parse_args()
    if args.command:
        args.func(args)
    else:
        parser.print_help()
    
if __name__ == '__main__':
    main()