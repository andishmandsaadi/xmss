import os
import hashlib

class HORS:
    def __init__(self, key_size=256):
        self.key_size = key_size  # Number of keys in the keyset
        self.private_keys = [os.urandom(32) for _ in range(key_size)]  # Generate private keys
        self.public_keys = [hashlib.sha256(k).hexdigest() for k in self.private_keys]  # Hash private keys to get public keys

    def sign(self, message):
        digest = hashlib.sha256(message.encode()).hexdigest()
        # Convert the first few characters of the digest into an integer to select a private key
        key_index = int(digest[:2], 16) % self.key_size
        return self.private_keys[key_index], key_index

    def verify(self, message, signature):
        private_key, key_index = signature
        digest = hashlib.sha256(message.encode()).hexdigest()
        # Recompute the key index from the message
        expected_key_index = int(digest[:2], 16) % self.key_size
        # Verify the public key matches the hashed signature
        return key_index == expected_key_index and self.public_keys[key_index] == hashlib.sha256(private_key).hexdigest()

# Example usage
hors = HORS()
message = "Hello, World!"
signature = hors.sign(message)
verification_result = hors.verify(message, signature)

print(verification_result)
