# Secure-Hearts

## Main goal
Implement a secure hearts game that supports the portuguese citizencard.


The game security system has to assure:
* Identity and authentication of players
* Confidential and random card distribution
* Honesty assurance
* Correct game evolution
* Correct accounting

The personal identification is made with recourse to the Portuguese Citizenship Card, with 
the public keys in the card and the validation of the certificate chain. 
They can also be emulated without the PT e-id, but will not assure identification.

## Execution
In order to execute both server and clint you must have Python3 installed and someof the 
required libraries:

```bash
$ pip3 install -r requirements.txt
```

If not present, create the client keys and logs path
```bash
$ cd src/client
$ mkdir keys && mkdir log
```

To run the server, just make sure you have port 8080 free and execute the command:
```bash
$ cd src/server
$ python3 start_server.py
```

To open a client console:
```bash
$ cd src/client
$ python3 secure_client.py
```

There is also present a script in src/client (`clear_clients.sh`) to delete the contents 
of the keys and log directories.
```bash
$ cd src/client
$ chmod +x delete_accounts.sh
$ ./clear_clients.sh
```

## TODO
### Missing stuff
#### Server & Client
- Support certificate validation
- Support secure message deciphering
- Support secure message ciphering
#### Server
- Support secure start on server side
- Support multiple tables
- Support multiple players
#### Client
- Support certificates for non-CC users
- Support multiple actions

Last Update: 26 Dec 2019

José Paiva
Alexandre Machado