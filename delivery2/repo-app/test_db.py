from api import app, db

def test_connection():
    with app.app_context():  
        try:
            db.create_all()  
            print("Conexão com o banco de dados bem-sucedida!")
        except Exception as e:
            print(f"Erro na conexão: {str(e)}")

if __name__ == "__main__":
    test_connection()
