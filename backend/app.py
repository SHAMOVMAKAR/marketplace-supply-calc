# -*- coding: utf-8 -*- 
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from datetime import datetime
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key') # Используем переменную окружения

# Инициализация базы данных и миграции
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Модель для хранения API-ключей
class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    marketplace = db.Column(db.String(50), nullable=False)  # WB, Ozon, Yandex
    api_key = db.Column(db.String(255), nullable=False)

    user = db.relationship('User', backref=db.backref('api_keys', lazy=True))

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Новое поле

# Регистрация пользователя
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Пользователь зарегистрирован!'})

# Авторизация (логин)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({'access_token': access_token})
    
    return jsonify({'message': 'Неверный email или пароль'}), 401

# Получение информации о пользователе (только для авторизованных)
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    })

@app.route('/add_api_key', methods=['POST'])
@jwt_required()
def add_api_key():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    marketplace = data.get('marketplace')
    api_key = data.get('api_key')

    if not marketplace or not api_key:
        return jsonify({"error": "Необходимо указать marketplace и api_key"}), 400

    new_key = APIKey(user_id=current_user_id, marketplace=marketplace, api_key=api_key)
    db.session.add(new_key)
    db.session.commit()

    return jsonify({"message": f"API-ключ для {marketplace} сохранен"}), 201

@app.route('/get_api_keys', methods=['GET'])
@jwt_required()
def get_api_keys():
    current_user_id = get_jwt_identity()
    keys = APIKey.query.filter_by(user_id=current_user_id).all()

    return jsonify([
        {"marketplace": key.marketplace, "api_key": key.api_key} for key in keys
    ])

@app.route('/delete_api_key', methods=['DELETE'])
@jwt_required()
def delete_api_key():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    marketplace = data.get('marketplace')

    if not marketplace:
        return jsonify({"error": "Необходимо указать marketplace"}), 400

    key = APIKey.query.filter_by(user_id=current_user_id, marketplace=marketplace).first()
    
    if not key:
        return jsonify({"error": f"API-ключ для {marketplace} не найден"}), 404

    db.session.delete(key)
    db.session.commit()

    return jsonify({"message": f"API-ключ для {marketplace} удален"}), 200


if __name__ == '__main__':
    app.run(debug=True)
