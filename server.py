#TODO: add multithreading to handle multiple clients

import socket

import datetime

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(('127.0.0.1', 8080))

server.listen(2)

print('Server listening on port 8080...')

#what server is doing
while True:

    client, addr = server.accept()
    print(f'connected from {addr}')

    while True:
        data = client.recv(1024)

        if not data:
            print('client disconnected')
            break

        timestamp = datetime.datetime.now()
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        msg = data.decode()
        print(f'[{timestamp_str}] client: {msg}')

        client.send('message recieved'.encode())

    client.close()


