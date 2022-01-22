import os
import auth
import Util
import rsa
import rsa.randnum

db = auth.DBConnection()
curseur = db.cursor()
print('------------ PROJET SECURITE ------------')
print('Please type the number of the desired choice:')
print('1. Register')
print('2. Login')
print('3. Menu')
rep = input('> ')
if(rep == '1'):
    print('---- REGISTRATION:')
    auth.signUp(curseur, db)
    print('user successfully registered')
    os.system("python main.py")
if(rep == '2'):
    print('---- Login:')
    logged, user = auth.login(curseur, db)
    print(logged)
    if (logged):
        print('user successfully loggged in')
        os.system("python menu.py")
    if (logged==False):
        print('user unsuccessfully loggged in')
elif (rep == '3'):
    print('---- to get to the menu you must Login:')
    logged, user = auth.login(curseur, db)
    print(logged)
    if (logged):
        print('user successfully loggged in')
        os.system("python menu.py")
    if (logged==False):
        print('user unsuccessfully loggged in')
    
else:
    print('please write a valid choice')
