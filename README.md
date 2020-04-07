# :lock: Password Manager

## Why Password Manager

  * Rather than using one or two passwords you can think of, to use over every website you visit, makes you vulnerable,
  since it's easy to hack you once the hacker get hold of that password.
  * So, it better to use a strong, random password and having so many random passwords, makes it difficult to remember them
  all. It's better to have a password manager like this to manage all your passwords efiiciently.
  * This password manager provides all the features of creating random passwords and storing them securely with powerful encryption.

## Command Line Password Manager for linux, windows, python script
 
  * It uses your key / password to create a base64 encrypted key to encrypt your passwords in your database.
  * Even if some could able to get hands on your database, they can't see the passwords unless they have your password and salt file.
  * You can even connect this password manager to remote database, with which you can access your encrypted passwords from everywhere.
  * As it's a command line script, you might find it difficult to get started. But, once you get to know the 
  power of command line / terminal, well everything has a start. 
  * If you want to make some changes to this script, feel free to do it.
  * If you find any difficulty in getting started, [check this section.](#usage)
  
## Requirements

  * python3
  * python cryptography module

## Usage

### Create Password

 ```
 password_manager.py -c <application> 
 password_manager.py --create <application>
 ```
  * This creates a password for the **application**, and stores them after encryption and displays it on the terminal
  
### Update Password

 ```
 password_manager.py -u <application> 
 password_manager.py --update <application>
 ```
  * This creates a password for the **application**, if already doesn't exists.
  * If already exists if updates the password and displays it after storing them in your database.
  
### Get Password

  ```
 password_manager.py -g <application> 
 password_manager.py --get <application>
 ```
  * This displays the password stored (if exists) for the application.
  
### Delete Password

  ```
 password_manager.py -d <application> 
 password_manager.py --delete <application>
 ```
  * This deletes the password stored (if exists ) for the application.
  
### List Passwords

  ```
  password_manager.py --list
  ```
  * This displays all the passwords stored in the database
  
### Length of Passwords

  ```
  password_manager.py -c <application> -l <length_of_the_password>
  password_manager.py --create <application> --length <length_of_the_password>
  ```
  * These -l, --length are optional and are to define the length of the password you want to have.
  * By default the length is 10. But, if you like to be more difficult to be cracked, feel free to the increase that number. 
  
### Update User Key / Password

  ```
  password_manager.py --update_user_key
  ```
  * If you ever feel like to update the key / password you provided ( incase someone got hold of your key ), this command will take care of that.
 
### Help
  
  ```
  password_manager.py --help
  password_manager.py -h
  ```
  * Those both commands helps with all the commands you can use and how to use.
  
## Contact

 * :email: mail me at suryasantosh14523@gmail.com
 * Instagram Id: surya_yellapu14523
  
