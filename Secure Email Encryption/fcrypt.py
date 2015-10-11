__author__ = 'vishalrao'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os


def encrypt(destination_public_key, sender_private_key, input_plain_text, cipher_text):

    # AES Encryption:
    with open(input_plain_text) as f:
        plain_text = f.read()
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(plain_text) + encryptor.finalize()

    # Private key loading/generation:
    # private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(sender_private_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None,backend=default_backend())

    # Signing the message:
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256()
    )
    signer.update(ct)
    signature = signer.finalize()

    # Encrypting the AES key:
    with open(destination_public_key, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    key_cipher_text = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    parts = [iv, key_cipher_text, ct, signature]

    complete_cipher_message = '+++'.join(parts)

    with open(cipher_text, "w") as f:
        f.write(complete_cipher_message)


def decrypt(destination_private_key, sender_public_key, cipher_text, output_plain_text):

    with open(cipher_text) as f:
        ct = f.read()
    parts = ct.split('+++')
    iv = parts[0]
    key_cipher_text = parts[1]
    ct = parts[2]
    signature = parts[3]

    # Verifying signature
    with open(sender_public_key) as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    verifier = public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(ct)
    verifier.verify()

    # decrypting the key:
    with open(destination_private_key) as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None,backend=default_backend())

    aes_key = private_key.decrypt(
        key_cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # using AES key to decrypt the message and write to file:
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ct) + decryptor.finalize()
    with open(output_plain_text, "w") as f:
        f.write(plain_text)


def main(argv):
    if argv[0] == '-e':
        if len(argv) < 4:
            print "too few arguments passed for encryption"
            print "usage : python fcrypt.py -e destination_public_key_filename sender" \
                  "_private_key_filename input_plaintext_file ciphertext_file"
            exit(0)
        else:
            destination_public_key = str(argv[1])
            sender_private_key = str(argv[2])
            input_plain_text = str(argv[3])
            cipher_text = str(argv[4])
            encrypt(destination_public_key, sender_private_key, input_plain_text, cipher_text)

    elif argv[0] == '-d':
        if len(argv) < 4:
            print "too few arguments passed for decryption"
            print "usage: python fcrypt.py -d destination_private_key_filename sender_" \
                  "public_key_filename ciphertext_file output_plaintext_file"
            exit(0)
        else:
            destination_private_key = str(argv[1])
            sender_public_key = str(argv[2])
            cipher_text = str(argv[3])
            output_plain_text = str(argv[4])
            decrypt(destination_private_key, sender_public_key, cipher_text, output_plain_text)

    else:
        print "option given is wrong, use either -e for encrypting or -d for decrypting."
        exit(0)


if __name__ == "__main__" :
    import sys
    main(sys.argv[1:])