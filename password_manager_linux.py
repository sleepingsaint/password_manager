#!/usr/bin/python3
import os, string, random, csv, sqlite3, sys, getpass, argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode

# creating string arrays
lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
digits = string.digits

BASE_DIR = os.path.dirname(__file__)
DATABASE_FILE_NAME = os.path.join(BASE_DIR, 'passwords.db')
KEY_SALT_FILE_PATH = os.path.join(BASE_DIR, 'salt')
USER_KEY_FILE_PATH = os.path.join(BASE_DIR, 'user_key')
DATABASE_NAME = 'passwords'

conn = sqlite3.connect(DATABASE_FILE_NAME)
cursor = conn.cursor()

# get user password
def get_user_password():
    password = getpass.getpass(prompt = "Enter your key/password to encrypt passwords : ", stream=None)
    confirm_password = getpass.getpass(prompt = "Confirm your key/password : ", stream=None)

    if password == confirm_password:
        return password
    
    # incase if passwords doesn't match
    retry = input('Password doesnot match. Want to retry again? (Y / N) : ')
    while retry != "N":
        if retry == "Y":
            get_user_password()
        else:
            retry = input('Wrong Input. Want to retry again? (Y / N) : ')

    # trying to change user's mind
    print("Passwords are encrypted in database with your password, so no other can access it.")    
    retry = input("Want to retry again? (Y / N) : ")
    while retry != "N":
        if retry == "Y":
            get_user_password()
        else:
            retry = input('Wrong Input. Want to retry again? (Y / N) : ')
    return False 

# generate new salt
def generate_salt():
    with open(KEY_SALT_FILE_PATH, 'w+b') as saltfile:
        salt = os.urandom(16)
        saltfile.write(salt)
        return salt

# generate new fernet key
def generate_fernet_key():
    user_password = get_user_password()

    if not user_password:
        exit()
        
    salt = generate_salt()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(user_password.encode()))
    
    with open(USER_KEY_FILE_PATH, 'w+b') as keyfile:
        keyfile.write(key)
    
    return key
    
# create fernet from user password / key
def get_fernet_key():
    # checking if the key file exists or not
    if os.path.exists(USER_KEY_FILE_PATH):
        with open(USER_KEY_FILE_PATH, 'rb') as keyfile:
            key = keyfile.read()
            return key
    
    return generate_fernet_key()

# encrypt password helper function
def encrypt_password(password):
    fernet = Fernet(get_fernet_key())
    password = fernet.encrypt(password.encode()) 
    return password

# decrypt password helper function
def decrypt_password(password):
    fernet = Fernet(get_fernet_key())
    password = fernet.decrypt(password.encode())
    return password

# create random password
def generate_password(length):
    characters_array = lowercase + uppercase + digits
    password = str()

    for x in range(length):
        password += random.choice(characters_array)
    return password

# checking if the table exists
def check_table():
    cursor.execute("SELECT count(?) FROM sqlite_master WHERE type='table'", (DATABASE_NAME ,))

    # creating a table with DATABASE_NAME if it doesn't exists
    if(cursor.fetchone()[0] != 1):
        cursor.execute("CREATE TABLE "+ DATABASE_NAME +" (service text, password text)")
        conn.commit()

# get password of the service, if exists
def check_service(service):
    cursor.execute("SELECT password FROM "+ DATABASE_NAME +" WHERE service=?", (service ,))
    return cursor.fetchone()

# add password to the database
def create_password(service, length):
    # checking if table exists
    check_table()

    if check_service(service) is None:
        password_ = generate_password(length)
        password = encrypt_password(password_).decode()
        cursor.execute("INSERT INTO "+ DATABASE_NAME +" VALUES (?, ?)", (service, password))
        conn.commit()
        print("password for the " + service + ' - ' + password_)
    else:
        print('Password already exists for ' + service)

# get password of the service
def get_password(service):
    check_table()
    if check_service(service) is None:
        print("Password doesn't exists for " + service)
        return
    password = check_service(service)[0]
    password = decrypt_password(password).decode()
    print(service + " - " + password)

# update password with the new length
def update_password(service, length):
    if check_service(service) is None:
        create_password(service, length)
    else:
        check_table()
        password_ = generate_password(length)
        password = encrypt_password(password_).decode()
        cursor.execute("UPDATE "+ DATABASE_NAME +" SET password=? WHERE service=?", (password, service))
        conn.commit()
        print('Updated Successfully! - ' + password_) 

# list all the passwords
def list_passwords():
    check_table()
    cursor.execute("SELECT * FROM " + DATABASE_NAME)
    passwords_list = cursor.fetchall()
    return passwords_list

# delete the password
def delete_password(service):
    check_table()
    if check_service(service) is None:
        print('Password for ' + service + " is not in the database")
    else:
        cursor.execute("DELETE FROM " + DATABASE_NAME + " WHERE service=?", (service,))
        conn.commit()
        print('Password Deleted Successfully')

# updating the user key
def update_user_key():

    # retrieving the stored passwords
    passwords_tuple = list_passwords()
    passwords_list = []
    for service, password in passwords_tuple:
        passwords_list.append([service, decrypt_password(password).decode()])

    # generating the new fernet key
    key = generate_fernet_key()

    # deleting the old tables
    cursor.execute("DROP TABLE " + DATABASE_NAME)
    conn.commit()

    # encrypting the passwords with the new key
    passwords_ = []
    for service, password in passwords_list:
        passwords_.append((service, encrypt_password(password).decode()))

    # creating a new table
    check_table()
    cursor.executemany("INSERT INTO " + DATABASE_NAME + " VALUES (?, ?)", passwords_)
    conn.commit()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog="CLI Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''\
             Command Line Password Manager
             --------------------------------
                * Passwords are stored after strong encryption
                * The key and salt files are required to decrypt the passwords
                  So, carefull while deleting those files.
         ''')
    
    # settings command line arguments
    parser.add_argument("-c", "--create", nargs="*", help="add password")
    parser.add_argument("-g", "--get", nargs="*", help="get password")
    parser.add_argument("-u", "--update", nargs="*", help="update password")
    parser.add_argument("-d", "--delete", nargs="*", help="delete password")
    parser.add_argument("-l", "--length", help="length of the password (optional). Default set to 10", default=10)
    parser.add_argument("--list", action="store_true", help="list all the passwords")
    parser.add_argument("--update_user_key", action="store_true", help="Update the user key")

    args = parser.parse_args()
    
    # executing the helper functions
    if args.create is not None:
        for arg in args.create:
            create_password(arg, int(args.length))

    if args.get is not None:
        for arg in args.get:
            get_password(arg)

    if args.update is not None:
        for arg in args.update:
            update_password(arg, int(args.length))

    if args.delete is not None:
        for arg in args.delete:
            delete_password(arg)

    if args.list:
        passwords_list = list_passwords()
        if len(passwords_list) > 0:
            for service, password in passwords_list:
                print(service + " - " + decrypt_password(password).decode())
        else:
            print("No passwords yet")

    if args.update_user_key:
        update_user_key()