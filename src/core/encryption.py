import os
import base64
import hashlib
from typing import Tuple, Dict

# Post-Quantum Key Encapsulation (Kyber-512 / ML-KEM-512)
from pqcrypto.kem import ml_kem_512

# Symmetric Encryption (AES-GCM 256-bit)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QuantumEncryption:
    """
    Quantum-resistant hybrid encryption scheme (Centralized).
    
    Mechanisms:
    1. Key Encapsulation: Kyber-512 (ML-KEM-512) -> Shared Secret.
    2. Key Derivation: SHA-256(Shared Secret) -> AES-256 Key.
    3. Data Encryption: AES-256-GCM.
    
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
        
    def export_public_key(self) -> str:
        """Returns Base64 encoded public key."""
        return base64.b64encode(self.public_key).decode('utf-8')

    def encrypt_message(self, target_public_key: bytes, message_text: str) -> Dict[str, bytes]:
        """
        High-level encryption function.
        Generates ephemeral keys, encrypts the message, and returns all needed artifacts.
        
        Args:
            target_public_key (bytes): Recipient's Kyber public key.
            message_text (str): Plaintext message.
            
        Returns:
            dict: {
                'kyber_capsule': bytes,  # Encapsulated key (send to specific target)
                'aes_nonce': bytes,      # 12-byte IV for AES-GCM
                'ciphertext': bytes      # Encrypted message payload (includes tag)
            }
        """
        # 1. Kyber Encapsulation (Key Exchange)
        # Generates 'capsule' (to send) and 'shared_secret' (keep hidden)
        kyber_capsule, shared_secret_raw = ml_kem_512.encrypt(target_public_key)
        
        # 2. Key Derivation (HKDF is better, but SHA256 is sufficient for this scope)
        # We ensure the AES key is exactly 32 bytes (256 bits)
        aes_key = hashlib.sha256(shared_secret_raw).digest()
        
        # 3. Symmetric Encryption (AES-GCM)
        nonce = os.urandom(12) # Standard 96-bit nonce
        aesgcm = AESGCM(aes_key)
        
        # AESGCM.encrypt returns ciphertext + tag
        ciphertext = aesgcm.encrypt(nonce, message_text.encode('utf-8'), None)
        
        return {
            'kyber_capsule': kyber_capsule,
            'aes_nonce': nonce,
            'ciphertext': ciphertext
        }

    def decrypt_message(self, packet: Dict[str, bytes]) -> str:
        """
        High-level decryption function.
        
        Args:
            packet (dict): Must contain 'kyber_capsule', 'aes_nonce', 'ciphertext'.
            
        Returns:
            str: Decrypted plaintext message.
            
        Raises:
            RuntimeError: If secret key is missing.
            ValueError/InvalidTag: If decryption fails (Bad key or tampering).
        """
        if not self.secret_key or all(b == 0 for b in self.secret_key):
             raise RuntimeError("Secret key has been wiped from memory.")

        kyber_capsule = packet.get('kyber_capsule')
        aes_nonce = packet.get('aes_nonce')
        ciphertext = packet.get('ciphertext')
        
        if not (kyber_capsule and aes_nonce and ciphertext):
            raise ValueError("Incomplete packet dictionary.")

        # 1. Kyber Decapsulation
        # Recover the raw shared secret using our private key
        try:
            shared_secret_raw = ml_kem_512.decrypt(self.secret_key, kyber_capsule)
        except Exception as e:
            raise ValueError(f"Kyber decapsulation failed: {e}")

        # 2. Key Derivation (Must match encrypt_message)
        aes_key = hashlib.sha256(shared_secret_raw).digest()
        
        # 3. Symmetric Decryption
        aesgcm = AESGCM(aes_key)
        
        # Decrypt (Raises InvalidTag if integrity check fails)
        plaintext_bytes = aesgcm.decrypt(aes_nonce, ciphertext, None)
        
        return plaintext_bytes.decode('utf-8')

    def wipe_memory(self):
        """Destroys the secret key in memory."""
        if self.secret_key:
            self.secret_key = b'\x00' * len(self.secret_key)
