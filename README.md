# crypto_list
---

## Requirements

- Python 3
- cryptography >= 1.8.1

## Usage

### Starting the application

python crypto_list.py

or

download [win](http://www.pedroboechat.com/downloads/crypto_list_win64.zip) or [linux](http://www.pedroboechat.com/downloads/crypto_list_linux64.zip) _amd64_ binary distribution, and run crypto_list.

### Saving a list

1. Run the application.

![](http://www.pedroboechat.com/images/crypto-list-1.png)


2. Add a new entry.

![](http://www.pedroboechat.com/images/crypto-list-2.png)


3. Save entries to an encrypted list file (\*.crypto_list).

![](http://www.pedroboechat.com/images/crypto-list-3.png)

![](http://www.pedroboechat.com/images/crypto-list-4(2).png)


4. Create a new salt (to be hashed along with your master key). You'll need the salt along with your master key to decrypt this list later, so save it to a file (\*.salt) and keep the file in a safe place!

![](http://www.pedroboechat.com/images/crypto-list-5.png)

![](http://www.pedroboechat.com/images/crypto-list-6.png)


5. Define a master key. You'll need memorize the master key to decrypt this list later.

![](http://www.pedroboechat.com/images/crypto-list-7.png)


### Opening a list

1. Run the application.

![](http://www.pedroboechat.com/images/crypto-list-1.png)


2. Open an encrypted list file (\*.crypto_list).

![](http://www.pedroboechat.com/images/crypto-list-8.png)

![](http://www.pedroboechat.com/images/crypto-list-9.png)


3. Load the salt used to encrypt the list you're trying to open along with your master key.

![](http://www.pedroboechat.com/images/crypto-list-10.png)

![](http://www.pedroboechat.com/images/crypto-list-11.png)


4. Input the master key you used to encrypt the list you're trying to open.

![](http://www.pedroboechat.com/images/crypto-list-12.png)


### Disclaimer

The software is provided "as is". Use it at your own risk. If you forget your master key or lose your salt file, I won't be able to help you.
