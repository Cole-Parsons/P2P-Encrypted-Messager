# Secure P2P Encrypted Chat  
A peer-to-peer chat application written in Python that establishes a secure, encrypted channel between two clients using modern cryptography. Peers discover each other via a lightweight rendezvous server, then communicate directly over TCP with end-to-end encryption.  

## Features  
* End-to-end encryption  
* X25519 Diffie-Hellman key exchange  
* HKDF (SHA-256) for key derivation  
* AES-256-GCM authenticated encryption  
* Per-message random nonces  
* Direct peer-to-peer TCP connection  
* Concurrent send/recieve via threading  

## How to Run  
### Requirements  
* Python 3.10+  
* cryptography library `pip install cryptography`  

Start rendezvous server `python server.py`  

Start two clients in seperate terminals (ensure port arguments are two different numbers)  
`python client.py 5001`  
`python client.py 5002`  

Now start chatting!  

## Road Map  
* Authentification(TOFU or key fingerprints)  
* Replay protection via message counters(AAD)  
* NAT traversal  
* Multi-peer chat suppor  
