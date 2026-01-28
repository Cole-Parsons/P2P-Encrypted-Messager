# Identity key: Ed25519
# Key exchange: X25519
# Message encryption: ChaCha20-Poly1305 (better for software)
# Hashing and operating system secure rnd num: SHA-256

#Create user Identity, A long term cryptographic key pair that proves "this is me"
#   -Need private and public Ed25519 key

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

#Generate Private key
private_key = ed25519.Ed25519PrivateKey.generate()

#Get corresponding public key
pubic_key = private_key.public_key()
