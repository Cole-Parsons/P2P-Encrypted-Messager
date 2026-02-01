#TODO: give clients other clients info ip/port so they can connect to each other

import socket
import datetime
import threading
import time

connected_clients = {}
clients_lock = threading.Lock()
id_counter = 0

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 8080))
server.listen(2)
print('Server listening on port 8080...')

while len(connected_clients) < 2:
    client, addr = server.accept()
    id_counter += 1

    client_id = f'client{id_counter}'
    ip, port = addr

    connected_clients[f'client{id_counter}'] = {
        'socket': client,
        'ip': ip,
        'port': 8081 if id_counter == 1 else 8082,
        'role': 'listener' if id_counter ==1 else 'connector'
        }

    print(f'{client_id} connected from {addr}')

c1 = connected_clients['client1']
c1_ip = connected_clients['client1']['ip']
c1_port = connected_clients['client1']['port']
c1_role = connected_clients['client1']['role']

c2 = connected_clients['client2']
c2_ip = connected_clients['client2']['ip']
c2_port = connected_clients['client2']['port']
c2_role = connected_clients['client2']['role']

#send client 1 data to client 2
c1_data = f'{c1_ip}:{c1_port}:{c1_role}'
c2['socket'].send(c1_data.encode())
c2['socket'].close()

#send client2 data to client1
c2_data = f'{c2_ip}:{c2_port}:{c1_role}'
c1['socket'].send(c2_data.encode())
c1['socket'].close()
