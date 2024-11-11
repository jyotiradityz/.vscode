#-------------------------------------------------------------------------# SHA-1 
import hashlib
import sys

def sha1_hash(data):
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.hexdigest()

data = sys.argv[1].encode()
print(sha1_hash(data))


#-------------------------------------------------------------------------DSS

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes

# Generate a DSA private key
private_key = dsa.generate_private_key(key_size=2048)


message = b"This is a message for digital signature."

# Sign the message using the private key
signature = private_key.sign(
    message,
    hashes.SHA256()
)


print(f"Signature: {signature.hex()}")

# Verify the signature using the public key
public_key = private_key.public_key()

try:
    # The Prehashed class allows the use of precomputed hash objects when verifying signatures
    public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )
    print("Signature verified successfully!")
except Exception as e:
    print("Signature verification failed:", str(e))
