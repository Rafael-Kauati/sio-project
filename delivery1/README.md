# Project members :

### Rafael kauati - 105925
### Vasco Vouzela - 108130
### Alírio Rego   - 

# Major features implemented for this delivery :
* Confidentiality over the requests made to the server, performed by a hybrid encryption where the content of the request is firstly encrypted with a symmetric key and the symmetric key is sent it ciphred by the a public key of a key pair of the server (only the server can decrypt the content) 
* Protection over replay attacks with NONCE that is provided by the server to the client and must be used in the next request made by the client, the server checks the existence of the nonce in the DB, checks if it was already used, perform ther operation of the request and returns a new NONCE to be used by the client in the next request that needs it
* The decrypt file feature allows multiply types of decryption algorithms, in the project it was used only encryption with ChaCha20, but, if having the correct encryption metadata, it should be able to decrypt any encrypt file
* Check the 3° topic to test all the commands implemented

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

### Then you can run the flask app with run-flask-app.sh file at the delivery1/repo-app/, this script also set the env vars to be used by the client, regarding the public key and server address

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
bash rep_subject_credentials "password" "credentials"
```
<hr>

To create a new organization :
```bash
bash rep_create_org "Org4" "anon3" "anon3" "anon3@example.com" "credentials"  
```
<hr>

To list all organizations :
```bash
bash rep_list_orgs
```
<hr>

To create a new session in that organization :
```bash

bash rep_create_session "Org4"  "anon3"  "password"   "credentials" "session_file" 
```
<hr>


To create a new subject :
```bash
bash rep_subject_credentials "password2" "credentials"
bash rep_add_subject "session_file" "gabs" "gabs" "gabs@gmail.com"  "credentials"
bash rep_create_session "Org4"  "gabs"  "password" "credentials" "session_file"
```
<hr>

To list the subjects of the organization :
```bash
bash rep_list_subjects  "session_file"
```
<hr>

To upload a document with the session(note: this command assumes that the document is not encrypted, so it encrypts it and sends the encrypted key, encryptography data and the file handle within the request) :
```bash
bash rep_add_doc "session_file" "test" "./test"
```
<hr>

To list files from an organization of the session key :
```bash
bash rep_list_docs "session_file"
```
<hr>

To get document metadata (the encryption metadata is stored in local file to be used in the decryption command) :
```bash
bash rep_get_doc_metadata "session_file" "test"
```
<hr>

To download the file (change the hash value of to the correct file handle printed from the previous command) :
Note : This method receive the content of the file encrypted from the server, if its not readable, then returns as hex value 
```bash
bash rep_get_file d8c3b75e09249b626be4fb9ff7de83867e3fcd6f1afa664c5131d81055ac8867 
```
Thats why we recommend to test with the -f/--file option to write the encrypted content in the file directly so can be used in the nexts commands
```bash
bash rep_get_file d8c3b75e09249b626be4fb9ff7de83867e3fcd6f1afa664c5131d81055ac8867 -f "output"
```
<hr>

To decrypt an encrypted document (the document must be in the local machine), the decrypted data is also stored at a {encrypted_file}_decrypted file (automatically) :
```bash
bash rep_decrypt_file "output" "test_encryption_data.json"
```
<hr>

To delete document :
```bash

bash rep_delete_doc "session_file" "test"
```
