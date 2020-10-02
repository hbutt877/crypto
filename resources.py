from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel,ExchangeModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import re
from flask import request,jsonify
import requests
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired,BadTimeSignature

API_KEY = 'b72d5b0f-9505-4063-9104-5d7a1c314562'

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)

s = URLSafeTimedSerializer('Thisisasecret!')


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}

        new_user = UserModel(
            username = data['username'],
            isverified = False,
            password = UserModel.generate_hash(data['password'])
        )

        try:
            new_user.save_to_db()
            # access_token = create_access_token(identity = data['username'])
            # refresh_token = create_refresh_token(identity = data['username'])
            # return {
            #     'message': 'User {} was created'.format(data['username']),
            #     'access_token': access_token,
            #     'refresh_token': refresh_token
            #     }
            return {'message': 'user created'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        else:
            if(current_user.isverified is False):
                return {'error': 'Not verified'}
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            l = len(access_token)
            print(access_token)
            bytes_token = list(bytes(access_token[-10:],'utf-8'))
            for i in range(len(bytes_token)):
              bytes_token[i] = bytes_token[i] + 7
            b = "".join(map(chr, bytes_token))
            access_token2 = access_token[:l-10] + b
            tmp = access_token2[:200] + access_token2[230:] + access_token2[200:230]
            # tmp2 = tmp[:200] + tmp[-30:]+ tmp[200:(l-30)]
            # bytes_token = list(bytes(access_token[-10:],'utf-8'))
            # for i in range(len(bytes_token)):
            #   bytes_token[i] = bytes_token[i] - 7
            # b = "".join(map(chr, bytes_token))
            # access_token3 = access_token[:l-10] + b
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'username' : current_user.username,
                'access_token': access_token
                }
        else:
            return {'message': 'Wrong credentials'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        id = UserModel.find_by_username("b").id

        # exchange = ExchangeModel(
        #     userid = id,
        #     exchangeid = "zJT6d2mHDyV"
        # )
        # exchange.save_to_db()

        print(id)
        exchanges = ExchangeModel.find_by_userid(id)
        print(exchanges)
        for i in exchanges:
            print(i.id,i.userid,i.exchangeid)
        # return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }
class GetExchangeResource(Resource):
    @jwt_required
    def get(self):
        id = request.args.get('id',default=0)
        if(id==0):
            return jsonify({'error': 'invalid id'})
    #Remove dummy before deployment
    #Remove dummy before deployment
    #Remove dummy before deployment
        # if(id=="dummy"):
        #     a = {"address_from":"34NjfWgoeH41M4MNdmi8LdSsRMG9qTcDpY","address_to":"GBH4TZYZ4IRCPO44CBOLFUHULU2WGALXTAVESQA6432MBJMABBB4GIYI","amount_from":"1","amount_to":"125258.30224260","currency_from":"btc","currency_to":"xlm","expected_amount":"1","extra_id_from":None,"extra_id_to":"abcd","id":"LKuAYqAUwMM","status":"finished","timestamp":"2020-09-13T19:23:24.767Z","tx_from":"input hash example","tx_to":"output hash example","type":"floating","updated_at":"2020-09-14T19:24:18.247Z"}
        #     return jsonify(a)
        session = requests.Session()
        session.trust_env = False
        a = session.get('https://api.simpleswap.io/v1/get_exchange?api_key={}&id={}'.format(API_KEY,id))
        if(a.status_code<400 and a.status_code>=200):
            a = a.json()
            a.pop('currencies', None)
        else:
            return jsonify({'error': 'may be invalid id'})
        return a

class CreateExchangeResource(Resource):
    @jwt_required
    def post(self):
        data = request.get_json(force=True)
        amount = data.get("amount")
        address= data.get("address")
        depositCurrency = data.get('depositcurrency')
        receiveCurrency = data.get('receivecurrency')
        extraid = data.get('extraid')
        fixed = data.get('fixed')
        if(fixed=="true" or fixed=="True" or fixed is True):
            fixed = "true"
        else:
            fixed = ""

        # new_amount = requests.get('https://api.simpleswap.io/v1/get_estimated?api_key=b72d5b0f-9505-4063-9104-5d7a1c314562&fixed=false&currency_from=btc&currency_to=eth&amount='+amount).text
        if(extraid=='' or extraid is None):
            r = requests.post('https://api.simpleswap.io/v1/create_exchange?api_key='+API_KEY,json={"fixed": fixed, "currency_from":depositCurrency,"currency_to":receiveCurrency,"address_to":address,"amount":amount})
        else:
            r = requests.post('https://api.simpleswap.io/v1/create_exchange?api_key='+API_KEY,json={"fixed": fixed, "currency_from":depositCurrency,"currency_to":receiveCurrency,"address_to":address,"amount":amount,'extra_id_to':extraid})
        if(r.status_code<400 and r.status_code>=200):
            id = r.json()['id']
            return jsonify({'id': id})
        else:
            return jsonify({'id':-1})
class AddExchangeResource(Resource):
    @jwt_required
    def post(self):
        data = request.get_json(force=True)
        username = data.get("username")
        exchangeid = data.get("exchangeid")
        if(username is None or exchangeid is None):
            return jsonify({'error': 'Empty input'})
        id = UserModel.find_by_username(username).id
        if(id is None):
            return jsonify({'error': 'Username not found'})
        exchange = ExchangeModel(
            userid = id,
            exchangeid = exchangeid
        )
        try:
            exchange.save_to_db()
            return jsonify({'success':'saved successfully'})
        except Exception as e:
            print(e)
            return jsonify({'error': 'Unable to save exchangeid to database'})
class GetUserExchangeResource(Resource):
    @jwt_required
    def post(self):
        data = request.get_json(force=True)
        username = data.get("username")
        if(username is None):
            return jsonify({'error': 'Empty input'})
        exchangeid = UserModel.find_by_username(username).id
        if(exchangeid is None):
            return jsonify({'error': 'Username not found'})
        try:
            exchanges = ExchangeModel.find_by_userid(exchangeid)
            list_exchanges = []
            for i in exchanges:
                list_exchanges.append(i.exchangeid)
            return jsonify({'exchanges': list_exchanges})
        except Exception as e:
            print(e)
            return jsonify({'error': 'Unable to retrieve exchanges'})
class ConfirmEmailResource(Resource):
    def get(self):
        try:
            token  = request.args.get('token',default=0)
            if(token==0):
                return {'error': 'Enter token'}
            email = s.loads(token, salt='email-confirm', max_age=3600)
            a = UserModel.find_by_username(email)
            if(a.isverified is True):
                return {'success': 'Already verified'}
            UserModel.update_isverified(email)
            # a = UserModel.find_by_username(email)
            # print(a.isverified)
            return {'success': email}
        except SignatureExpired:
            return {'error': 'Expired token'}
        except BadTimeSignature:
            return {'error': 'Wrong token'}
        except Exception as e:
            print(e)
            return {'error': 'Unknown'}
