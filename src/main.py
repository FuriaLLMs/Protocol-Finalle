import asyncio
import sys
import hashlib
import logging
from typing import NoReturn

import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

# Import local modules
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.security import ram_guard
    from src.core.identity import QuantumIdentity
    from src.core.encryption import QuantumEncryption
    from src.core.peer_manager import PeerManager
    from src.network import quic_server
    from src.network.p2p_client import send_handshake, send_tactical_message
except ImportError as e:
    print(f"{Fore.RED}[CRITICAL] Module import failed: {e}")
    sys.exit(1)

# Configure Logging (suppress low level logs for clean UI)
logging.basicConfig(level=logging.CRITICAL) 

async def async_input(prompt: str) -> str:
    """
    Reads input asynchronously to avoid blocking the event loop.
    """
    return await asyncio.get_running_loop().run_in_executor(None, input, prompt)

async def main_loop(
    identity: QuantumIdentity,
    encryption: QuantumEncryption,
    peer_manager: PeerManager,
    port: int
):
    """
    Main application loop with Command processing.
    """
    print(f"\n{Fore.CYAN}--- TACTICAL P2P TERMINAL ACTIVE ---{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Commands: {Fore.YELLOW}/connect <IP> {Fore.WHITE}| {Fore.YELLOW}/list {Fore.WHITE}| {Fore.YELLOW}/msg <NODE_ID> <MSG>{Fore.WHITE} | {Fore.YELLOW}/exit\n")

    while True:
        try:
            # Show prompt
            user_input = await async_input(f"{Fore.GREEN}CMD > {Fore.WHITE}")
            command = user_input.strip()
            
            if not command:
                continue

            # --- COMMAND PROCESSING ---
            if command.lower() in ["/exit", "/quit"]:
                raise KeyboardInterrupt

            elif command.startswith("/connect "):
                # /connect 192.168.1.5
                parts = command.split()
                if len(parts) < 2:
                    print(f"{Fore.RED}Usage: /connect <TARGET_IP> [PORT]")
                    continue
                
                target_ip = parts[1]
                target_port = int(parts[2]) if len(parts) > 2 else 4433 # Default port
                
                print(f"{Fore.YELLOW}Initiating Handshake with {target_ip}:{target_port}...")
                try:
                    await send_handshake(
                        target_ip, 
                        target_port, 
                        identity, 
                        encryption, 
                        listening_port=port
                    )
                    print(f"{Fore.GREEN}Handshake sent.")
                except Exception as e:
                    print(f"{Fore.RED}Handshake Failed: {e}")

            elif command.startswith("/list"):
                # /list
                peers = peer_manager.list_peers()
                print(f"\n{Fore.CYAN}=== KNOWN ALLIES ==={Style.RESET_ALL}")
                if not peers:
                    print(f"{Fore.YELLOW}No allies found. Use /connect to find peers.")
                else:
                    for peer in peers:
                        print(f"{Fore.WHITE}- {peer}")
                print("")

            elif command.startswith("/msg "):
                # /msg <NODE_ID> <MESSAGE TEXT>
                parts = command.split(" ", 2)
                if len(parts) < 3:
                    print(f"{Fore.RED}Usage: /msg <NODE_ID_PARTIAL> <MESSAGE>")
                    continue
                
                target_id_partial = parts[1]
                message_text = parts[2]
                
                # Verify Peer exists
                # We need to find the full node_id from partial match
                target_node_id = None
                target_peer = None
                
                for nid, data in peer_manager.peers.items():
                    if nid.startswith(target_id_partial):
                        target_node_id = nid
                        target_peer = data
                        break
                
                if not target_peer:
                    print(f"{Fore.RED}Unknown ally: {target_id_partial}")
                    continue
                
                print(f"{Fore.BLUE}Encrypting & Sending to {target_node_id[:8]}...")
                try:
                    await send_tactical_message(
                        target_ip=target_peer['ip'],
                        target_port=target_peer['port'],
                        message=message_text,
                        my_identity=identity,
                        target_kyber_public_key=target_peer['kyber_pk'],
                        encryption_module=encryption
                    )
                    # print(f"{Fore.GREEN}Message Sent.") # p2p_client already logs this? No, it logs via logger which is suppressed.
                    print(f"{Fore.GREEN}>> SENT: {message_text}")
                except Exception as e:
                    print(f"{Fore.RED}Transmission Failed: {e}")

            else:
                print(f"{Fore.RED}Unknown command. Commands: /connect, /list, /msg, /exit")
            
        except EOFError:
            break
        except Exception as e:
            print(f"{Fore.RED}Error in main loop: {e}")

async def start_application():
    """
    Boot sequence and main execution.
    """
    identity = None
    encryption = None
    peer_manager = None
    
    print(f"{Fore.WHITE}{Style.BRIGHT}INITIALIZING QUANTUM RESISTANCE NODE...{Style.RESET_ALL}")
    
    # --- STEP 1: RAM GUARD ---
    print(f"{Fore.WHITE}Engaging RAM Guard... ", end="")
    if ram_guard.lock_memory(strict=False):
        print(f"{Fore.GREEN}[LOCKED]")
    else:
        print(f"{Fore.YELLOW}[WARNING: SWAP RISK]")
        print(f"{Fore.YELLOW}   Could not lock memory. Run as root or adjust ulimit for full security.")

    # --- STEP 2: CRYPTO INIT ---
    print(f"{Fore.WHITE}Generating Quantum Identity (Dilithium-2)... ", end="")
    try:
        identity = QuantumIdentity()
        
        # Calculate a Node ID for display
        pub_key_bytes = identity.public_key
        node_id = hashlib.sha256(pub_key_bytes).hexdigest()[:12].upper()
        
        print(f"{Fore.GREEN}[OK]")
        print(f"{Fore.WHITE}NODE ID: {Fore.MAGENTA}{node_id}")
        
    except Exception as e:
        print(f"{Fore.RED}[FAILED]")
        print(f"{Fore.RED}Critical Error: {e}")
        return

    print(f"{Fore.WHITE}Initializing Kyber-512 Encryption... ", end="")
    try:
        encryption = QuantumEncryption()
        print(f"{Fore.GREEN}[OK]")
    except Exception as e:
        print(f"{Fore.RED}[FAILED]: {e}")
        return

    print(f"{Fore.WHITE}Allocating Peer Manager (RAM)... ", end="")
    peer_manager = PeerManager()
    print(f"{Fore.GREEN}[OK]")

    # --- STEP 3: NETWORK STARTUP ---
    HOST = "0.0.0.0" # Listen on all interfaces
    PORT = 4433
    
    # Allow overriding port via args for testing multiple nodes on same machine
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
        except:
            pass
    
    print(f"{Fore.WHITE}Starting QUIC Tactic Server on port {PORT}... ", end="")
    
    # Start server as a background task
    server_task = asyncio.create_task(
        quic_server.start_node(
            HOST, 
            PORT, 
            identity_module=identity, 
            encryption_module=encryption,
            peer_manager=peer_manager
        )
    )
    # Give it a moment to bind
    await asyncio.sleep(0.5)
    print(f"{Fore.GREEN}[LISTENING]")

    # --- ENTER MAIN LOOP ---
    try:
        await main_loop(identity, encryption, peer_manager, PORT)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutdown sequence initiated...")
    finally:
        # --- CLEANUP ---
        if identity:
            print(f"{Fore.WHITE}Wiping cryptographic keys... ", end="")
            identity.wipe_memory()
            print(f"{Fore.GREEN}[WIPED]")
        
        if peer_manager:
            print(f"{Fore.WHITE}Purging peer list... ", end="")
            peer_manager.purge_peers()
            print(f"{Fore.GREEN}[PURGED]")
            
        print(f"{Fore.WHITE}Cleaning memory pages... ", end="")
        ram_guard.panic_clean()
        print(f"{Fore.GREEN}[CLEAN]")
        
        print(f"{Fore.RED}{Style.BRIGHT}SYSTEM HALTED.")
        
        # Cancel server task
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(start_application())
    except KeyboardInterrupt:
        pass # Already handled in start_application, but just in case
