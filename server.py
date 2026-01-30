#TODO: add multithreading to handle multiple clients

import socket
import datetime
import threading
import time

def allow_client():
    client, addr = server.accept()
    print(f'connected form {addr}')

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


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(('127.0.0.1', 8080))

server.listen(2)

print('Server listening on port 8080...')

#what server is doing

t1 = threading.Thread(target=allow_client, daemon=True)
t2 = threading.Thread(target=allow_client, daemon=True)

t1.start()
t2.start()

end = input('press enter to shut down server: ')



        
        
        
        

        

    


