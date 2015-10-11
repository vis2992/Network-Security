__author__ = 'vishalrao'
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
private_key1 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key1 = private_key1.public_key()
pem1 = private_key1.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pem_public1 = public_key1.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("destination_private_key.txt", "w") as f:
    f.write(str(pem1))

with open("destination_public_key.txt", "w") as f:
    f.write(str(pem_public1))
private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key2 = private_key2.public_key()
pem2 = private_key2.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pem_public2 = public_key2.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("sender_private_key.txt", "w") as f:
    f.write(str(pem2))
with open("sender_public_key.txt", "w") as f:
    f.write(str(pem_public2))
