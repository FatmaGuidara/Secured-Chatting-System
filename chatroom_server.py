import threading
import socket
import rsa
import rsa.randnum
import Util

# Localhost
host = '127.0.0.1'
# Port
port = 8080

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
names = []


def broadcast(message):
    for i in range(len(clients)):
        pubkey = rsa.key.PublicKey.load_pkcs1(names[i][1])
        encoded_rsa = Util._encrypt_rsa(pubkey, message.decode())
        clients[i].send(encoded_rsa)


def handle(client):
    while True:
        try:
            message = client.recv(1024)
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = names[index]
            broadcast(f'{nickname} left the chat'.encode('ascii'))
            names.remove(nickname)
            break


def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        client.send('NICK'.encode('ascii'))
        nickname = client.recv(1024).decode('ascii')
        pubkey = client.recv(1024)

        names.append((nickname, pubkey))
        clients.append(client)
        broadcast(f'{nickname} joined the chat!'.encode('ascii'))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


print('Server is listening...')
receive()

# fatma.guidara@insat.u-carthage.tn
# guidarafatma87@gmail.com