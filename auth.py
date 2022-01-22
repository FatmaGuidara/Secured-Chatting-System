import mysql.connector
import getpass
import hashlib
import string
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from user import User

def DBConnection():
    db = mysql.connector.connect(
        host="localhost",
        username="root",
        password="",
        db="chatroom"
    )
    return db

def send_email(email, token):
    msg = MIMEMultipart()
    msg['From'] = 'tpsecuriteinsat2022@gmail.com'
    msg['To'] = email
    msg['Subject'] = "Token d'authentification"
    message = f'Bonjour vous venez de connecter sur le ChatRoom. Voici votre token pour LE DOUBLE AUTH ! \n\n{token}'
    msg.attach(MIMEText(message))
    mailserver = smtplib.SMTP('smtp.gmail.com', 587)
    mailserver.ehlo()
    mailserver.starttls()
    mailserver.ehlo()
    mailserver.login('tpsecuriteinsat2022@gmail.com', 'chatroomSec2022')
    mailserver.sendmail('tpsecuriteinsat2022@gmail.com', email, msg.as_string())
    mailserver.quit()

def _generateSessionToken():
    S = 24
    ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k = S))
    ran = str(ran)
    ran = hashlib.sha256(ran.encode()).hexdigest()
    return ran

# Sign Up
def signUp(curseur, db):
    firstName = input('Firstname > ')
    lastName = input('Lastname > ')
    email = input('E-mail > ')
    try:
        password = getpass.getpass(prompt='Password > ')
        password = hashlib.sha256(password.encode()).hexdigest()
    except Exception as error:
        print('ERROR', error)
    try:
        password_confirm = getpass.getpass(prompt='Confirm password > ')
        password_confirm = hashlib.sha256(password_confirm.encode()).hexdigest()
    except Exception as error:
        print('ERROR', error)

    if(password == password_confirm):
        user = User(firstName, lastName, email, password)
        curseur.execute(
            f"insert into users(id, email, password, firstName,lastName) values (%s,%s,%s,%s,%s);",
            (user.id, user.email, user.password, user.firstName, user.lastName)
        )
        db.commit()
    else:
        print('Please verify')

# Sign In
def login(curseur, db):
    email = input('E-mail > ')
    try:
        password = getpass.getpass(prompt='Password > ')
        password = hashlib.sha256(password.encode()).hexdigest()
    except Exception as error:
        print('ERROR', error)
    try:
        curseur.execute(f"select * from users where email = '{email}'")
        user = curseur.fetchone()
        if (user[-1] == password):
            token = _generateSessionToken()
            curseur.execute(
                f"insert into tokens(email, token) values (%s,%s);",
                (email, token)
            )
            db.commit()
            send_email(email,token)
            token_sent = input('Veillez entrer votre token recu dans le e-mail ')
            if(token_sent == token):
                print(f'Hello {user[1]}, you re officially logged in. \n--- WELCOME TO THE CHATROOM')
            else:
                print('Arreter de pirater le compte!')
                return False , None
            return True, user
        else:
            return False , None
    except:
        print('please verify your credentials')
        return False, None

# Log out
def logout(curseur, db, email):
    curseur.execute(
        f"delete from tokens where email = '{email}';"
    )
    db.commit()
    print('user logged out')



# Main
db = DBConnection()
curseur = db.cursor()
# signUp(curseur, db)
# token = login(curseur, db)
# logout(curseur, db, 'b')
db.close()