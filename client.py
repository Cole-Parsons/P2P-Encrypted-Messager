#TODO: convert client to its own server so other client can connect

import socket
import threading
import time
import sys


peer_socket = None
listener_port = int(sys.argv[1])

def connect_to_peer(ip, port):
    global peer_socket
    while peer_socket == None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            peer_socket = s
        except ConnectionRefusedError:
            time.sleep(0.1)

def listener_for_peer(port):
    global peer_socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', port))
    s.listen(1)

    conn, addr = s.accept()
    peer_socket = conn
    print(f'Peer connected from {addr}')

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
    t = threading.Thread(target=connect_to_peer, args=(peer_ip, peer_port))
else:
    t = threading.Thread(target=listener_for_peer, args=(listener_port,))

t.start()

print(peer_socket)

counter = 0
while peer_socket is None:
    if counter == 0:
        print('waiting for connection')
    else:
        print('.')

    counter += 1
    time.sleep(0.5)

print(f'connected to {peer_port}')

while True:
    msg = input('>')
    
    peer_socket.send(msg.encode())    
    print(peer_socket.recv(1024).decode())



# timestamp = datetime.datetime.now()
#timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

#msg = data.decode()    
#print(f'[{timestamp_str}] {addr}: {msg}')
#client.send('message recieved'.encode())