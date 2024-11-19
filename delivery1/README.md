# How to install and prepare the env :

## 1° - Docker, used to have a postgresql database to allow data persistence in the repository:

### Run the docker container at the delivery1/repo-app/:

```bash
docker-compose build
docker-compose up
```

## 2° - The flask app, but before starting it, must install the virtual env:

### In other terminal, Create and install all the dependencies of the virtual env with the venv-and-install.sh file at the delivery1/repo-app/:

```bash
. venv-and-install.sh
```

### Then you can run the flask app with run-flask-app.sh file at the delivery1/repo-app/

```bash
. run-flask-app.sh
```

# How to test the client and the repository:

## 3° - In other terminal, travel to delivery1/repo-app/cmd-client, and enter the virtual env there: 
```bash
source venv/bin/activate
```

### Commands of the client (run at the delivery1/repo-app/cmd-client)
#### Note : all of these commands are also in delivery1/repo-app/cmd-client/commands.txt file

To create a key pair for a subject:
```bash
python3 client.py rep_subject_credentials "password" "credentials"
```

To create a new organization :
```bash
python client.py rep_create_org "Org4" "anon3" "anon3" "anon3@example.com" "credentials"  --repo "localhost:5000"
```

To create a new session in that organization :
```bash

python3 client.py rep_create_session "Org4"  "anon3"  "password"   "credentials" "session_file"  --key "../public_key.pem"
```


To create a new subject :
```bash
python3 client.py rep_subject_credentials "password2" "credentials"
python3 client.py rep_add_subject "session_file" "gabs" "gabs" "gabs@gmail.com"  "credentials"
python3 client.py rep_create_session "Org4"  "gabs"  "password" "credentials" "session_file"
```

To list the subjects of the organization :
```bash
python3 client.py rep_list_subjects  "session_file"
```

To upload a document with the session(note: this command assumes that the document is not encrypted, so it encrypts it and sends the encrypted key, encryptography data and the file handle within the request) :
```bash
python3 client.py rep_add_doc "session_file" "test" "./test"
```

To list files from an organization of the session key :
```bash
python3 client.py rep_list_docs "session_file"
```

To get document metadata (the encryption metadata is stored in local file to be used in the decryption command) :
```bash
python3 client.py rep_get_doc_metadata "session_file" "test"
```

To download the file (change the hash value of to the correct file handle printed from the previous command) :
```bash
python3 client.py rep_get_file d8c3b75e09249b626be4fb9ff7de83867e3fcd6f1afa664c5131d81055ac8867 -f  "output"
```

To decrypt an encrypted document (the document must be in the local machine), the decrypted data is also stored at a {encrypted_file}_decrypted file (automatically) :
```bash
python3 client.py rep_decrypt_file "output" "test_encryption_data.json"
```
To delete document :
```bash

python3 client.py rep_delete_doc "session_file" "test"
```