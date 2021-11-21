# AD Necronomicon
![AD Necronomicon](https://i.imgur.com/WvK1vPa.png)
![a passwort assesment tool for your active directory](https://i.imgur.com/M0dzy5n.pngg)



## What is this Ad Necronomicon
AD Necronomicon is a passwort assesment tool for your active directory. 
It compares all user und computer passwords against a list of your choice
You can provide your own local list or own backend or use the official backend

### The server never knows the whole hash and even the script does not know the real password behind the hash

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.

```bash
pip install -r requirements.txt
```

## Usage

```

usage: main.py [-h] [--key KEY] [--speed SPEED] [--backend BACKEND] [--offline] [--nossl] target

Lets take a little peak into the Necronomicon and look if we can find your Active Directory users in it

positional arguments:
  target             [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help         show this help message and exit
  --key KEY          The API-Key for the Backend
  --speed SPEED      The speed of the queries to the backend [slow,fast] slow: Partial hashes are send to the backend -> Slow search in the db fast: Full hash is send to backend ->       
                     faster search in db
  --backend BACKEND  Address of a custom Backend. Just use it if you know what you are doing!
  --offline          Using the offlinemode which does not use a backend
  --nossl            Using no SSl for Backend


Example:
py.exe .\main.py target=mylab.local/syncer:Abcdefghij1!@192.168.2.156  --backend=localhost:8080 --nossl --key=abc
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[Apache License 2.0](https://choosealicense.com/licenses/apache-2.0/)


## copyright and license notices 
❤This product includes software developed by SecureAuth Corporation (https://www.secureauth.com/)  

❤libs/smb.py and libs/nmb.py are based on Pysmb by Michael Teo (https://miketeo.net/projects/pysmb/)

❤libs/krb5/asn1.py and libs/krb5/types.py by Marc Horowitz

❤libs/krb5/crypto.py by the Massachusetts Institute of Technology
