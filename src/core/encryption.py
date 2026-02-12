import os
import base64
from typing import Tuple

# Post-Quantum Key Encapsulation (Kyber-512 / ML-KEM-512)
from pqcrypto.kem import ml_kem_512

# Symmetric Encryption (AES-GCM 256-bit)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QuantumEncryption:
    """
    Quantum-resistant hybrid encryption scheme.
    
    Mechanisms:
    1. Key Encapsulation: Kyber-512 (ML-KEM-512) establishes a shared secret.
    2. Data Encryption: AES-256-GCM uses the shared secret to encrypt payload.
    
    SECURITY CRITICAL:
    - Secret keys (`self.secret_key`) are kept in RAM only.
    - `wipe_memory()` must be called to destroy keys.
    """
    
    def __init__(self):
        """
        Generates a Kyber-512 keypair in volatile memory.
        """
        # public_key: Used by others to send encrypted messages to US.
        # secret_key: Used by US to decrypt incoming messages.
        self.public_key, self.secret_key = ml_kem_512.generate_keypair()
        
    def encapsulate(self, remote_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Generates a shared secret for a specific recipient.
        
        Args:
            remote_public_key (bytes): The recipient's Kyber public key.
            
        Returns:
            ciphertext (bytes): The encapsulated key (send this to recipient).
            shared_secret (bytes): The symmetric key (keep this secret).
        """
        # Library uses 'encrypt' for encapsulation
        ciphertext, shared_secret = ml_kem_512.encrypt(remote_public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Recovers the shared secret from an encapsulated ciphertext.
        
        Args:
            ciphertext (bytes): The encapsulated key received from sender.
            
        Returns:
            shared_secret (bytes): The symmetric key.
            
        Raises:
            ValueError: If decryption fails (implicit checks in Kyber).
        """
        if not self.secret_key or all(b == 0 for b in self.secret_key):
             raise RuntimeError("Secret key has been wiped from memory.")

        # Library uses 'decrypt' for decapsulation
        return ml_kem_512.decrypt(self.secret_key, ciphertext)

    @staticmethod
    def encrypt_message(message: str, shared_secret: bytes) -> bytes:
        """
        Encrypts a message using AES-GCM with the derived shared secret.
        
        Args:
            message (str): Plaintext message.
            shared_secret (bytes): Symmetric key (32 bytes).
            
        Returns:
            bytes: Nonce (12 bytes) + Ciphertext + Tag (16 bytes).
        """
        # AESGCM requires 12-byte nonce
        nonce = os.urandom(12)
        
        # Initialize AES-GCM with the shared secret
        aesgcm = AESGCM(shared_secret)
        
        # Encrypt
        ciphertext_with_tag = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        
        # Return bundled packet
        return nonce + ciphertext_with_tag

    @staticmethod
    def decrypt_message(encrypted_data: bytes, shared_secret: bytes) -> str:
        """
        Decrypts a message using AES-GCM.
        
        Args:
            encrypted_data (bytes): Nonce + Ciphertext + Tag.
            shared_secret (bytes): Symmetric key.
            
        Returns:
            str: Decrypted plaintext.
            
        Raises:
            InvalidTag: If integrity check fails.
        """
        # Extract nonce
        nonce = encrypted_data[:12]
        ciphertext_with_tag = encrypted_data[12:]
        
        # Initialize AES-GCM
        aesgcm = AESGCM(shared_secret)
        
        # Decrypt
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        
        return plaintext_bytes.decode('utf-8')

    def export_public_key(self) -> str:
        """Returns Base64 encoded public key."""
        return base64.b64encode(self.public_key).decode('utf-8')

    def wipe_memory(self):
        """Destroys the secret key in memory."""
        if self.secret_key:
            self.secret_key = b'\x00' * len(self.secret_key)
