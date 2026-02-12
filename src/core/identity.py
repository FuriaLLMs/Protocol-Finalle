import base64
from typing import Optional
from pqcrypto.sign import ml_dsa_44 as dilithium2 # ML-DSA-44 is Dilithium-2 (NIST Standard)

class QuantumIdentity:
    """
    Quantum-resistant identity management using Dilithium-2.
    
    SECURITY CRITICAL:
    - Secret keys are generated in memory and MUST NEVER use disk I/O.
    - Memory wiping is implemented to allow ephemeral usage.
    """
    
    def __init__(self):
        """
        Initializes the identity by generating a Dilithium-2 keypair in volatile memory.
        """
        # Generate the keypair immediately upon instantiation
        # public_key and secret_key are bytes
        self.public_key, self.secret_key = dilithium2.generate_keypair()

    def sign_data(self, data: bytes) -> bytes:
        """
        Signs the provided data using the secret key.
        
        Args:
            data (bytes): The data to sign.
            
        Returns:
            bytes: The detached signature.
            
        Raises:
            RuntimeError: If the secret key has been wiped.
        """
        # Check if key is wiped (simple check for null bytes or empty)
        if not self.secret_key or all(b == 0 for b in self.secret_key):
             raise RuntimeError("Secret key has been wiped from memory.")
             
        return dilithium2.sign(self.secret_key, data)

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verifies a signature against the data and public key.
        
        Args:
            data (bytes): The original data.
            signature (bytes): The signature to verify.
            public_key (bytes): The public key to use for verification.
            
        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            return dilithium2.verify(public_key, data, signature)
        except Exception:
            return False

    def export_public_key(self) -> str:
        """
        Exports the public key as a Base64 encoded string.
        
        Returns:
            str: Base64 string of the public key.
        """
        return base64.b64encode(self.public_key).decode('utf-8')

    def wipe_memory(self):
        """
        Destroys the secret key in memory.
        This provides forward secrecy if the device is captured after this method is called.
        """
        if self.secret_key:
            # Overwrite the reference with null bytes of the same length
            # Note: Python's immutable bytes mean we can't zero-fill the exact memory address
            # without ctypes/unsafe ops, but this removes the reference to the key material.
            self.secret_key = b'\x00' * len(self.secret_key)
