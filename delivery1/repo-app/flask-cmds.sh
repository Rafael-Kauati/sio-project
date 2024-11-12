#Setup the env for development
export FLASK_APP=api  
export FLASK_ENV=development
flask run

#In case needs to migrate changes on the DB 
#flask db init
#flask db migrate -m "migrate changes description"
#flask db upgrade


