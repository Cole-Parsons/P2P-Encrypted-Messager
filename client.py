#TODO: add quitting function, prevent MITM attacks(authentification), open it up to web, not just client local cli based, gui

import socket
import threading
import time
import sys
import datetime
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

peer_socket = None

listener_port = int(sys.argv[1])
peer_connected_event = threading.Event()
shutdown_event = threading.Event()

timestamp = datetime.datetime.now()
timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')


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
            print(f'{timestamp_str}: {msg_rdy}')

        except OSError:
            #socket closed elsewhere
            break

def recv_peer_key(event):
    event.wait()
    peer_public_bytes = peer_socket.recv(32)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return peer_public_key

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

print(peer_ip, peer_port)

if peer_role == 'listener':
   t = threading.Thread(target=listener_for_peer, args=(listener_port, peer_connected_event)) 
else:
    t = threading.Thread(target=connect_to_peer, args=(peer_ip, peer_port, peer_connected_event))
    
t.start()

print(peer_socket)
print(f'connected to {peer_port}')

peer_connected_event.wait()

peer_socket.send(
    public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
)
peer_public_bytes = peer_socket.recv(32)
peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)

shared_key = private_key.exchange(peer_public_key)

aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'p2p chat key',
    ).derive(shared_key)

aesgcm = AESGCM(aes_key)

sender_thread = threading.Thread(target=send_msg, args=(peer_connected_event, aesgcm, shutdown_event))
reciever_thread = threading.Thread(target=recv_msg, args=(peer_connected_event, aesgcm, shutdown_event))

sender_thread.start()
reciever_thread.start()
