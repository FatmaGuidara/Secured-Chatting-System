import socket
import threading
import auth
import Util
import rsa
import rsa.randnum

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 8080))

pubkey, privkey = Util._generate_keys_rsa()
x = pubkey.save_pkcs1()
y = rsa.key.PublicKey.load_pkcs1(x)


def receive(firstName):
    while True:
        message = client.recv(1024)
        try:
            message = rsa.decrypt(message, privkey)
            message = message.decode('ascii')
            print(f'{message}')
        except:
            message = message.decode('ascii')
            if (message == 'NICK'):
                client.send(firstName.encode('ascii'))
                client.send(x)
            else:
                print('An error occured!')
                client.close()
                break


def write(firstName):
    while True:
        message = input()
        if (message == 'exit'):
            return 0
        message = f'{firstName}> {message}'
        client.send(message.encode('ascii'))


# Main
db = auth.DBConnection()
curseur = db.cursor()

print('Welcome to ChatRoom')
print('1. Sign up')
print('2. I already have an account Login')
rep = input()
if (rep == '1'):
    auth.signUp(curseur, db)
elif (rep == '2'):
    logged, user = auth.login(curseur, db)
    while (logged == False):
        logged, user = auth.login(curseur, db)

    receive_thread = threading.Thread(target=receive, args=(user[1],))
    receive_thread.start()

    write_thread = threading.Thread(target=write, args=(user[1],))
    write_thread.start()

    receive_thread.join()
    write_thread.join()

    auth.logout(curseur, db, user[3])

db.close()
