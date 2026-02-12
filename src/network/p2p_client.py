import asyncio
import logging
import struct
from typing import Optional

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from src.core.identity import QuantumIdentity
from src.core.encryption import QuantumEncryption
from src.network.quic_server import generate_ephemeral_cert

# Configure logging
logger = logging.getLogger(__name__)

async def send_tactical_message(
    target_ip: str,
    target_port: int,
    message: str,
    my_identity: QuantumIdentity,
    target_kyber_public_key: bytes,
    encryption_module: QuantumEncryption # We need an instance to access encapsulation methods
):
    """
    Encodes, Encrypts, Signs, and Sends a message to a tactical node.
    
    Packet Structure:
    [SENDER_PUBKEY_LEN (4B)] + [SENDER_PUBKEY (Dilithium)] + 
    [SIGNATURE_LEN (4B)]     + [SIGNATURE] + 
    [CIPHERTEXT_LEN (4B)]    + [CIPHERTEXT (Kyber)] + 
    [PAYLOAD (Encrypted msg)]
    """
    logger.info(f"Preparing to send message to {target_ip}:{target_port}...")

    # 1. ENCAPSULATION (Kyber)
    # Generate shared secret using Target's Public Key
    logger.debug("Encapsulating secret...")
    ciphertext, shared_secret = encryption_module.encapsulate(target_kyber_public_key)
    
    # 2. ENCRYPTION (AES-GCM)
    # Encrypt the message payload
    logger.debug("Encrypting payload...")
    encrypted_payload = QuantumEncryption.encrypt_message(message, shared_secret)
    
    # 3. CONSTRUCT BODY TO SIGN
    # The signature should cover: Ciphertext + EncryptedPayload
    # (Binding the key exchange to the data)
    body_to_sign = ciphertext + encrypted_payload
    
    # 4. SIGNING (Dilithium)
    logger.debug("Signing packet...")
    signature = my_identity.sign_data(body_to_sign)
    
    # 5. PACKET ASSEMBLY
    # Lengths are 4 bytes, Big Endian
    sender_pubkey = my_identity.public_key
    
    packet = (
        struct.pack("!I", len(sender_pubkey)) + sender_pubkey +
        struct.pack("!I", len(signature)) + signature +
        struct.pack("!I", len(ciphertext)) + ciphertext +
        encrypted_payload
    )
    
    # 6. SEND VIA QUIC
    logger.info(f"Sending packet ({len(packet)} bytes)...")
    
    # Generate ephemeral config for the CLIENT side (QUIC requires TLS even for client)
    # In a real scenario, we might pinning server certs, but here we trust on first use/internal logic
    configuration = generate_ephemeral_cert()
    configuration.is_client = True
    
    # Disable TLS certificate verification (We rely on Dilithium/Kyber for tactical security)
    import ssl
    configuration.verify_mode = ssl.CERT_NONE
    
    # Connect and send
    try:
        async with connect(
            target_ip,
            target_port,
            configuration=configuration,
        ) as protocol:
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(stream_id, packet, end_stream=True)
            logger.info("Message sent successfully.")
            # Wait a brief moment to ensure data is flushed before closing
            await asyncio.sleep(0.5)
            protocol.close()
            await protocol.wait_closed()
            
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        raise e
