# AD Necronomicon
![alt text](https://i.imgur.com/WvK1vPa.png)
![alt text](https://i.imgur.com/M0dzy5n.pngg)



## What is this Ad Necronomicon
AD Necronomicon is a passwort assesment tool for your active directory. 
With an adminstrator account it gets all user hashes from a domain controller.
A part of the hash gets send to the backend and compared to a database.
All potential matches get send back and compared with the full hash.
If there is a match you will get informed about the weak/leaked password of the user.

### The server never knows the whole hash and even the script does not know the real password behind the hash

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.

```bash
pip install -r requirements.txt
```

## Usage

```python
py.exe .\main.py target=[domain]/[domainAdminUsername]:[domainAdminPassword]@[DC-IP]
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
