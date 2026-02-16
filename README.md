# Secure P2P Encrypted Chat  
A peer-to-peer chat application written in Python that establishes a secure, authenticated, end-to-end encrypted channel between two clients.  

Peers discover each other through a lightweight rendezvous server, then establish a direct TCP connection across networks (via public IP + port forwarding) and perform an authenticated cryptographic handshake before exchanging encrypted messages.  

## Features  
* End-to-end encryption  
* Cross-network peer connections (via public IP + exposed port)  
* X25519 Diffie-Hellman key exchange  
* Ed25519 Identity keys for peer authentication  
* Ephemeral key signing to prevent MITM attacks  
* HKDF (SHA-256) for key derivation  
* AES-256-GCM authenticated encryption  
* Peer identity fingerprinting (Trust On First Use model)  
* Per-message random nonces  
* Direct peer-to-peer TCP connection  
* Concurrent send/recieve via threading  

## Architecture Overview  
1. Both peers connect to a rendezvous server.  
2. The server exchanges each peer’s public IP and listening port.  
3. One peer connects directly to the other’s exposed port.  
4. Peers perform an authenticated key exchange:  
   * Exchange identity public keys  
   * Exchange ephemeral X25519 keys  
   * Sign ephemeral keys with Ed25519 identity keys  
   * Verify signatures  
5. A shared secret is derived and used for AES-GCM encryption.  
6. All chat messages are encrypted end-to-end.  
The rendezvous server is not involved after peer connection and cannot read encrypted messages.  

## How to Run  
### Requirements  
* Python 3.10+  
* cryptography library `pip install cryptography`  

### Start rendezvous server  
Run on a publically reachable machine (or port forwarded host)  
Start rendezvous server `python server.py <port>`  

### Expose one client's port  
One peer must:  
* Run in bridged mode (if using VM)  
* Forward a port on their router to their local machine  
* Start client with that exposed port:  
`python client_listener.py 5001`  

### Start connector client  
Second peer:  
`python client_connector.py 5002`  
Enter the rendezvous server's public IP address and port when prompted.  

Now both peers will establish a direct encrypted channel and begin chatting  

## Security Model  
* Ephemeral session keys provide forward secrecy.  
* Identity keys authenticate peers and prevent MITM attacks.  
* Peer fingerprints are stored locally (TOFU model).  
* AES-GCM ensures confidentiality + integrity.  
