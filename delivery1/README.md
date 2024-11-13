
## Create a New Organization


```bash
python client.py rep_create_org "Org4" "anon3" "anon3" "anon3@example.com" "../public_key.pem"



python3 client.py rep_create_session "Org4" "anon3" "password" "key" credentials session_file


python3 client.py rep_add_subject "session_file" "gabs" "gabs" "gabs@gmail.com" "key2" "credentials"


python3 client.py rep_list_subjects "session_file"


python3 client.py rep_add_doc "session_file" "test" "./test"


python3 client.py rep_list_docs "session_file"


python3 client.py rep_get_doc_metadata "session_file" "test"


python3 client.py rep_get_file 6490a5f0aa2b5e017278615b91f482f6fd8dd5a4973960c35fd074ca91534af5 -f "output"


python3 client.py rep_delete_doc "session_file" "test"



This format ensures that all the commands are clearly presented and ready to be copy-pasted into the terminal.
