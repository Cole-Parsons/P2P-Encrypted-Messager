

import socket
import datetime
import threading
import time

connected_clients = {'clients': []}
clients_lock = threading.Lock()
id_counter = 0


def allow_client(connected_clients):
    client, addr = server.accept()
    ip, port = addr

    global id_counter
    id_counter += 1

    print(f'\nclient{id_counter} connected form {addr}')

    with clients_lock:
        connected_clients[f'client{id_counter}'] = {
            'ip': ip,
            'port': port,
        }

    print(connected_clients)

    while True:
        try:
            data = client.recv(1024)

            if not data:
                print('client disconnected')
                break
            timestamp = datetime.datetime.now()
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')

            msg = data.decode()    
            print(f'[{timestamp_str}] {addr}: {msg}')
            client.send('message recieved'.encode())
        except:
            break

    client.close()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(('127.0.0.1', 8080))

server.listen(2)

print('Server listening on port 8080...')

#what server is doing

t1 = threading.Thread(target=allow_client, args=(connected_clients,), daemon=True)
t2 = threading.Thread(target=allow_client, args=(connected_clients,), daemon=True)

t1.start()
t2.start()

end = input('press enter to shut down server: \n')
