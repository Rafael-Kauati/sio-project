#Setup the env for development
export FLASK_APP=api  
export FLASK_ENV=development
export REP_ADDRESS="localhost:5000"
export REP_PUB_KEY="public_key.pem"
flask run

#In case needs to migrate changes on the DB 
#flask db init
#flask db migrate -m "migrate changes description"
#flask db upgrade


