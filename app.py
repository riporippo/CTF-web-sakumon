from flask import Flask, request, jsonify, render_template, redirect, url_for
import jwt
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'abcd'
app.config['JWT_ALGORITHM'] = 'HS256'

users = {
    "admin": {"password": "asrjola;dfjkopq4wru9o0w4fnjiq3w4rovnua9oiwpeuinoasxdfjk4ewnurtiopaw4rwerfaeraerfasdf", "role": "admin"},
    "user1": {"password": "user1", "role": "user"},
    "guest": {"password": "guest", "role": "guest"}
}

# --- ヘルパー関数 ---

def create_jwt_token(username, role):
    """JWTトークンを生成する"""
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30), # 有効期限30分
        'iat': datetime.datetime.utcnow(),
        # 'sub': username,
        'role': role
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

def decode_jwt_token(token):
    """JWTトークンをデコードし、検証する"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}

# --- デコレータ ---

def jwt_required(f):
    """JWT認証を必要とするエンドポイントのためのデコレータ"""
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization header is missing'}), 401

        try:
            token = auth_header.split(" ")[1] # "Bearer <token>" からトークン部分を取得
        except IndexError:
            return jsonify({'message': 'Token is malformed'}), 401

        payload = decode_jwt_token(token)

        if 'error' in payload:
            return jsonify({'message': payload['error']}), 401

        #request.current_user = payload['sub'] # デコードしたユーザー名をリクエストオブジェクトに追加
        request.current_user_role = payload['role'] # ロールも追加
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ # デコレータが正しく機能するための設定
    return decorated_function

def role_required(role):
    """特定のロールを持つユーザーのみアクセスできるエンドポイントのためのデコレータ"""
    def decorator(f):
        @jwt_required
        def decorated_function(*args, **kwargs):
            if request.current_user_role != role:
                return jsonify({'message': f'Access denied: {role} role required'}), 403
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# --- ルート ---

@app.route('/')
def index():
    return render_template('/index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    user_info = users.get(username)

    if user_info and user_info["password"] == password:
        token = create_jwt_token(username, user_info["role"])
        return jsonify({'message': 'Login successful', 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required
def protected_route():
    """JWTトークンがあればアクセスできるエンドポイント"""
    return jsonify({
        'message': f'JWT secret key: abcd',
    }), 200

@app.route('/admin_only', methods=['GET'])
@role_required('admin')
def admin_only_route():
    """'admin'ロールを持つユーザーのみアクセスできるエンドポイント"""
    return jsonify({
        'message': f'Great! Flag is here!.',
        "flag": 'flag{JvvT_T0k3n_is_1mp0rtaNt_9assvv0rD}'
    }), 200

@app.route('/user_only', methods=['GET'])
@role_required('user')
def user_only_route():
    """'user'ロールを持つユーザーのみアクセスできるエンドポイント"""
    return jsonify({
        'message': f'よく開こうと思ったね！ここにフラグはないよ！.',
    }), 200

if __name__ == '__main__':
    app.run(debug=True)