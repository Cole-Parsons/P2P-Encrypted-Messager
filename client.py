#TODO: expose a port on router so can do p2p on different machines.

import socket
import threading
import time
import sys
import datetime
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

ID_PRIVATE_FILE = 'identity_private.pem'
ID_PUBLIC_FILE = 'identity_public.pem'


private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

users_file = 'known_users.json'

peer_socket = None

listener_port = int(sys.argv[1])
peer_connected_event = threading.Event()
shutdown_event = threading.Event()

timestamp = datetime.datetime.now()

def connect_to_peer(ip, port, event):
    global peer_socket
    while peer_socket == None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            print(f'connector : printing socket as s {s}')
            peer_socket = s
            print(f'printing socket as peer socket {peer_socket}')
        except ConnectionRefusedError:
            time.sleep(0.1)
    event.set()

def listener_for_peer(port, event):
    global peer_socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print(f'printing socket as s for listener {s}')
    s.bind(('127.0.0.1', port))
    s.listen(1)

    conn, addr = s.accept()
    print(f'printing socket (conn) after accept {conn}')
    peer_socket = conn
    print(f'peer_socket in listener: {peer_socket}')
    print(f'Peer connected from {addr}')
    event.set()

def send_msg(event, aesgcm, shutdown_event):
    event.wait()
    print('Connected Start chatting!')
    print('Enter "quit" to leave')
    while not shutdown_event.is_set():
        msg = input('')
        if msg == 'quit':
            shutdown_event.set()
            peer_socket.shutdown(socket.SHUT_RDWR)
            peer_socket.close()
            return
        plaintext = msg.encode()
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        peer_socket.send(nonce + ciphertext)

def recv_msg(event, aesgcm, shutdown_event):
    event.wait()
    while not shutdown_event.is_set():
        try:
            data = peer_socket.recv(4096)
            if not data:
                shutdown_event.set()
                break
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = aesgcm.decrypt(nonce,ciphertext, None)
            msg_rdy = plaintext.decode()

            if msg_rdy == 'quit':
                shutdown_event.set()
                break
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            print(f'{timestamp_str}: {msg_rdy}')

        except OSError:
            #socket closed elsewhere
            break

def recv_peer_key(event):
    event.wait()
    peer_public_bytes = peer_socket.recv(32)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return peer_public_key

def fingerprint(pubkey_bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pubkey_bytes)
    return digest.finalize().hex()

def save_known_users(file):
    with open(file, 'w') as f:
        json.dump(known_users, f, indent=2)

#create/load pub&priv keys
def load_create_identity_key():
    #checking private
    if os.path.exists(ID_PRIVATE_FILE):
        with open(ID_PRIVATE_FILE, 'rb') as f:
            priv = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        with open (ID_PRIVATE_FILE, 'wb') as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(ID_PUBLIC_FILE, 'wb') as f:
            f.write(priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return priv

#start send & recieve msg threads
def begin_chatting():
    sender_thread = threading.Thread(target=send_msg, args=(peer_connected_event, aesgcm, shutdown_event))
    reciever_thread = threading.Thread(target=recv_msg, args=(peer_connected_event, aesgcm, shutdown_event))
    sender_thread.start()
    reciever_thread.start()

identity_private = load_create_identity_key()
identity_public = identity_private.public_key()

signature = identity_private.sign(
    public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
)

known_users = {}

if os.path.exists(users_file):
    try:
        with open(users_file, 'r') as f:
            known_users = json.load(f)
    except json.JSONDecodeError:
        print('known users is curropted or empty, resetting')
        known_users = {}
        
rendezvous = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
rendezvous.connect(('127.0.0.1', 8080))

rendezvous.send(str(listener_port).encode())

print('Connected to server')
print('Waiting for other client to connect')

data = rendezvous.recv(1024).decode()

if not data:
    raise RuntimeError('Server closed without sending peer error')
peer_ip, peer_port, peer_role = data.split(':')
peer_port = int(peer_port)
rendezvous.close()

if peer_role == 'listener':
   t = threading.Thread(target=listener_for_peer, args=(listener_port, peer_connected_event)) 
else:
    t = threading.Thread(target=connect_to_peer, args=(peer_ip, peer_port, peer_connected_event))
    
t.start()

print(f'connected to {peer_port}')

peer_connected_event.wait()



#Send id pub key
my_identity_pub_bytes = identity_public.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
peer_socket.send(my_identity_pub_bytes)

#Recv peer pub key
peer_identity_public_bytes = peer_socket.recv(32)
peer_identity_public = ed25519.Ed25519PublicKey.from_public_bytes(
    peer_identity_public_bytes
)

#Send eph key
my_ephemeral_pub_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
peer_socket.send(my_ephemeral_pub_bytes)

#Recv eph key
peer_ephemeral_pub_bytes = peer_socket.recv(32)
peer_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
    peer_ephemeral_pub_bytes
)

#create & send signature
my_signature = identity_private.sign(my_ephemeral_pub_bytes)
peer_socket.send(my_signature)

#recv peer signature
peer_signature = peer_socket.recv(64)

#verify peer identity
try:
    peer_identity_public.verify(
        peer_signature,
        peer_ephemeral_pub_bytes
    )
except Exception:
    print('peer authentification failed! MITM?')
    peer_socket.close()
    sys.exit()

print('peer signature verified')

#Finger print peer identity
peer_fingerprint = fingerprint(peer_identity_public_bytes)

name = input('enter your name: ')
peer_socket.send(name.encode())
peer_name = peer_socket.recv(1024).decode()

if peer_name in known_users:
    if known_users[peer_name] != peer_fingerprint:
        print('Identity key changed, possible reinstall or impersonation.')
        print('continue y/n')
        choice = input('>')
        if choice.lower() != 'y':
            peer_socket.close()
            sys.exit()
else:
    print('New user detected. Saving finger print')

            
#if new user
known_users[peer_name] = peer_fingerprint

save_known_users(users_file)

shared_key = private_key.exchange(peer_ephemeral_public)

aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'p2p chat key',
    ).derive(shared_key)

aesgcm = AESGCM(aes_key)

begin_chatting()
