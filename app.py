from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user,current_user,logout_user,login_required
import pymysql
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@localhost:3306/flask-crud'


login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "credenciais autenticadas com sucesso"})

    return jsonify({"message": "credenciais invalidas"})


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    
    return jsonify ({"message": "Logout realizado com sucesso"})


@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

        user = User(username=username, password=hashed_password, roles = "user")
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuario criado com sucesso"}) , 200

    return jsonify({"message": "Dados invalidos"})


@app.route("/user/<int:id_user>", methods=["GET"])
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return jsonify({"username": user.username}), 200
    
    return jsonify({"message": "Usuario nao encontrado"}),404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    user = User.query.get(id_user)
    data = request.json
    
    if id_user != current_user and current_user.roles == "user":
        return jsonify({"message": "Operação nao permitida"}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso"}) , 200
    
    return jsonify({"message": "Usuario nao encontrado"}) , 404

@app.route("/user/<int:id_user>",methods=["DELETE"])
def delete_user(id_user):
    user = User.query.get(id_user)
    if current_user.roles != "admin":
        return jsonify({"message": "Operação nao permitida"}), 403
    
    if id_user == current_user.id:
        return jsonify({"message": "Deleção nao permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit() 
        return jsonify({"message": "Usuario Deletado com Sucesso"}) , 200
    
    return jsonify({"message": "Usuario não Encontrado"})


@app.route("/")
def hello_world():
    return "HELLO WOLRD"

if __name__== "__main__":
    app.run(debug=True)