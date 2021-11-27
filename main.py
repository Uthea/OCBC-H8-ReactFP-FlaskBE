#   an simple flask backend
from flask import Flask, json, jsonify, request, make_response
from flask_cors import CORS
############################ Choose Models ############################
# from dbms.json_db.model import Model
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jti, decode_token, \
    jwt_required
from flask_migrate import Migrate
from flask_pydantic import validate
from pydantic import BaseModel, EmailStr, constr
from werkzeug.security import check_password_hash, generate_password_hash

from config import BaseConfig
from model.user import db, User, Tokenlist

from dbms.dict_db.model import Model


############################ Initialization ############################

def create_app():
    app = Flask(__name__)
    app.config.from_object(BaseConfig())
    with app.app_context():
        db.init_app(app)

    return app


app = create_app()
migrate = Migrate(app, db)
jwt = JWTManager(app)

# use legit db
# this essitial for Cross Origin Resource Sharing with React frontend
# https://flask-cors.readthedocs.io/en/latest/
CORS(app)
# use database
model = Model()


##########################  API Implementation #########################
############################## create name #############################
@app.route('/keys', methods=["POST"])
@jwt_required()
def create_name():
    data_json = request.data
    data_dict = json.loads(data_json)
    # bad request
    if "key" not in data_dict:
        return jsonify({"errorMsg": "bad request"}), 400
    if not (model.create(data_dict["key"], data_dict)):
        return jsonify({"errorMsg": "bad request"}), 400
    # succeed
    return jsonify(data_dict), 201


############################## read name ###############################
@app.route('/keys/<key>', methods=["GET"])
@jwt_required()
def read_name(key):
    value = model.read(key)
    # not found
    if (value is None):
        return jsonify({"key": key, "errorMsg": "not found"}), 404
    # succeed
    value["key"] = key
    return jsonify(value), 200


############################## update name #############################
@app.route('/keys/<key>', methods=["PUT"])
@jwt_required()
def update_name(key):
    value = json.loads(request.data)
    # bad request
    if (not model.update(key, value)):
        return jsonify({"key": key, "errorMsg": "bad request"}), 400
    # succeed
    value["key"] = key
    return jsonify(value), 200


############################## delete name #############################
@app.route('/keys/<key>', methods=["DELETE"])
@jwt_required()
def delete_name(key):
    # not found
    value = model.read(key)
    if not value:
        return jsonify({"key": key, "errorMsg": "not found"}), 404
    # not found
    if (not model.delete(key)):
        return jsonify({"key": key, "errorMsg": "not found"}), 404
    # succeed
    value["key"] = key
    return jsonify(value), 200


############################# Debug Method #############################
# print database
@app.route('/debug', methods=["GET"])
@jwt_required()
def print_database():
    database = model.debug()
    if (database is None):
        print("\n########### Debug Method Not Implemented #############")
        return jsonify({"errorMsg": "Debug Method Not Implemented"}), 200
    else:
        print("\n######################################################")
        print(database)
        return jsonify(database), 200


############################## Auth ####################################
class LoginBodyModel(BaseModel):
    email: EmailStr
    password: str


class RegisterBodyModel(BaseModel):
    email: EmailStr
    username: str
    password: constr(min_length=6)


class RefreshBodyModel(BaseModel):
    access_token: str
    refresh_token: str


@app.route('/login', methods=["POST"])
@validate()
def login(body: LoginBodyModel):
    email = body.email
    password = body.password

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return make_response(jsonify({'msg': 'Wrong Email or Password'}), 400)

    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)

    token = Tokenlist(jti=get_jti(access_token), refresh_token=refresh_token, used=False)

    db.session.add(token)
    db.session.commit()

    return jsonify(access_token=access_token, refresh_token=refresh_token)


@app.route('/register', methods=["POST"])
@validate()
def register(body: RegisterBodyModel):
    email = body.email
    username = body.username
    password = body.password

    user_by_email = User.query.filter_by(email=email).first()
    user_by_name = User.query.filter_by(username=username).first()

    if user_by_email:
        return make_response(jsonify({'msg': f"Email {email} already exist in db"}), 400)

    if user_by_name and user_by_name.username == username:
        return make_response(jsonify({'msg': f"Username already exist in db"}), 400)

    new_user = User(email=email, username=username, password=generate_password_hash(password))

    db.session.add(new_user)
    db.session.commit()

    return make_response(jsonify({'msg': "Register Succeed !"}), 201)


@app.route('/refreshToken', methods=["POST"])
@validate()
def refresh_token(body: RefreshBodyModel):
    access_token = body.access_token
    refresh_token = body.refresh_token

    decode_token(refresh_token)  # will return 401 if token expired
    decoded_access_token = decode_token(access_token, allow_expired=True)

    identity = decoded_access_token['sub']
    jti = decoded_access_token['jti']

    result = Tokenlist.query.filter_by(jti=jti).first()

    if result:
        if result.used:
            return make_response(jsonify(msg='Refresh Token already used'), 400)
        elif result.refresh_token != refresh_token:
            return make_response(jsonify(msg='Access Token and Refresh Token doesnt Match'), 400)
        else:
            result.used = True

            new_access_token = create_access_token(identity=identity)
            new_refresh_token = create_refresh_token(identity=identity)

            token = Tokenlist(jti=get_jti(new_access_token), refresh_token=new_refresh_token, used=False)

            db.session.add(token)
            db.session.commit()

            return jsonify(access_token=new_access_token, refresh_token=new_refresh_token)
    else:
        return make_response(jsonify(msg='Access Token not found'), 400)


############################ Main Function #############################
if __name__ == "__main__":
    # run backend server on http://localhost:5000/
    app.run(host='localhost', port=5000, debug=True)
