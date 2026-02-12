import time
import ipaddress
from typing import Dict, Optional, List, Union

class PeerManager:
    """
    Manages the list of known allies (Peers) in VOLATILE MEMORY.
    
    Stores:
    - Node ID (Hash of Public Key or unique identifier)
    - IP Address & Port
    - Cryptographic Keys (Dilithium & Kyber)
    - Last Seen Timestamp
    """
    
    def __init__(self):
        self.peers: Dict[str, Dict] = {}

    def add_peer(self, 
                 node_id: str, 
                 ip: str, 
                 port: int, 
                 dilithium_pk: bytes, 
                 kyber_pk: bytes):
        """
        Adds or updates a peer in the known list.
        
        Args:
            node_id (str): Unique identifier for the peer.
            ip (str): IP address.
            port (int): Port number.
            dilithium_pk (bytes): Dilithium-2 Public Key for verification.
            kyber_pk (bytes): Kyber-512 Public Key for encryption.
            
        Raises:
            ValueError: If validation fails.
        """
        # 1. Validation
        if not node_id:
            raise ValueError("Node ID cannot be empty.")
        
        if not dilithium_pk:
            raise ValueError("Dilithium Public Key cannot be empty.")
            
        if not kyber_pk:
            raise ValueError("Kyber Public Key cannot be empty.")

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        # 2. Storage
        self.peers[node_id] = {
            "ip": ip,
            "port": port,
            "dilithium_pk": dilithium_pk,
            "kyber_pk": kyber_pk,
            "last_seen": time.time()
        }

    def get_peer(self, node_id: str) -> Optional[Dict]:
        """Returns the peer data if exists."""
        return self.peers.get(node_id)

    def remove_inactive_peers(self, timeout: int = 300) -> int:
        """
        Removes peers that haven't been seen in `timeout` seconds.
        Returns the number of removed peers.
        """
        now = time.time()
        to_remove = [
            nid for nid, data in self.peers.items() 
            if now - data["last_seen"] > timeout
        ]
        
        for nid in to_remove:
            del self.peers[nid]
            
        return len(to_remove)

    def list_peers(self) -> List[str]:
        """Returns a formatted list of online peers."""
        peer_list = []
        now = time.time()
        
        for nid, data in self.peers.items():
            last_seen_delta = int(now - data['last_seen'])
            status = "ONLINE" if last_seen_delta < 60 else "IDLE"
            
            peer_list.append(
                f"Node {nid[:8]}... [{status}] - {data['ip']}:{data['port']} (Last seen: {last_seen_delta}s ago)"
            )
        return peer_list

    def purge_peers(self):
        """
        SECURITY CRITICAL:
        Wipes the peer list from memory immediately.
        Use in case of Panic or Shutdown.
        """
        self.peers.clear()
