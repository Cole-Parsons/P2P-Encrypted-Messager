import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 8080))

print('Connected to server, type quit to exit')


while True:
    msg = input('>')

    if msg.lower() == 'quit':
        client.close()
        exit()

    client.send(msg.encode())    
    print(client.recv(1024).decode())

client.close()