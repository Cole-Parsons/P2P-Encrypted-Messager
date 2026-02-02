#TODO: convert client to its own server so other client can connect

import socket
import threading
import time
import sys

peer_socket = None
listener_port = int(sys.argv[1])
peer_connected_event = threading.Event()

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


def send_msg(event):
    event.wait()
    while True:
        msg = input('> ')
        peer_socket.send(msg.encode())


def recv_msg(event):
    event.wait()
    while True:
        data = peer_socket.recv(1024)
        if not data:
            break
        print(data.decode())


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

connection = True

sender_thread = threading.Thread(target=send_msg, args=(peer_connected_event,))
reciever_thread = threading.Thread(target=recv_msg, args=(peer_connected_event,))

peer_connected_event.wait()

sender_thread.start()
reciever_thread.start()


# timestamp = datetime.datetime.now()
#timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

#msg = data.decode()    
#print(f'[{timestamp_str}] {addr}: {msg}')
#client.send('message recieved'.encode())