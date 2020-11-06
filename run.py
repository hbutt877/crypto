# from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask import Flask, redirect, url_for, render_template, request,jsonify
import requests
import sys
import time
import urllib3
import json
from timeloop import Timeloop
import datetime
import re
from flask_cors import CORS, cross_origin
import _thread
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired,BadTimeSignature

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
mail = Mail(app)
api = Api(app)
CORS(app,resources={r"/*":{"origins":"*"}})
s = URLSafeTimedSerializer('Thisisasecret!')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'

db = SQLAlchemy(app)
import views, models, resources
db.create_all()
db.session.commit()
print(1)


app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

# import views, models, resources
api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.GetExchangeResource, '/getexchange')
api.add_resource(resources.CreateExchangeResource, '/createexchange')
api.add_resource(resources.AddExchangeResource, '/addexchange')
api.add_resource(resources.GetUserExchangeResource, '/getuserexchange')
api.add_resource(resources.ConfirmEmailResource, '/confirmemail')





API_KEY = 'b72d5b0f-9505-4063-9104-5d7a1c314562'
pairs = None
fixedpairs = None
allCurrencies = None

def test1():
    global pairs
    session = requests.Session()
    session.trust_env = False
    pairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY)).json()

def test2():
    global fixedpairs
    session = requests.Session()
    session.trust_env = False
    fixedpairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed=true'.format(API_KEY)).json()

def test3():
    global allCurrencies
    session = requests.Session()
    session.trust_env = False
    allCurrencies = session.get('https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY).json()

_thread.start_new_thread(test3,())
_thread.start_new_thread(test2,())
_thread.start_new_thread(test1,())

tl = Timeloop()

@tl.job(interval=datetime.timedelta(seconds=10))
def sample_job():
    _thread.start_new_thread(test3,())
    _thread.start_new_thread(test2,())
    _thread.start_new_thread(test1,())
    print(0,file=sys.stderr)



# @app.before_first_request
# def create_tables():
#     db.create_all()
#     db.session.commit()



@app.route("/login", methods=["GET"])
@jwt_required

def login():
    global pairs
    global fixedpairs
    global allCurrencies
    session = requests.Session()
    session.trust_env = False
    if(allCurrencies is None):
        allCurrencies = session.get('https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY).json()
    if(pairs is None):
        pairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY)).json()
    if(fixedpairs is None):
        fixedpairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed=true'.format(API_KEY)).json()

    depositCurrency = []
    tmp = pairs.keys()
    tmp = list(tmp)
    tmp.sort()
    name = ''
    image = ''
    for i in tmp:
        for j in allCurrencies:
            if(j["symbol"] == i):
                name = j["name"]
                image = "https://simpleswap.io"+j["image"]
        depositCurrency.append({'symbol':i,'name':name,'image':image})
    return jsonify(depositCurrency)

@app.route('/getcurrencies')
def getCurrencies():
    global pairs
    global fixedpairs
    global allCurrencies



    fixed = request.args.get('fixed',default=0)
    if(fixed==0):
        return jsonify({'error': 'incomplete input'})
    session = requests.Session()
    session.trust_env = False
    if(allCurrencies is None):
        allCurrencies = session.get('https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY).json()
    if(pairs is None):
        pairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY)).json()
    if(fixedpairs is None):
        fixedpairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed=true'.format(API_KEY)).json()
    keys = None
    if(fixed=="true" or fixed == True or fixed=="True"):
        keys = list(fixedpairs.keys())
    else:
        keys = list(pairs.keys())
    r = []
    for i in keys:
        for j in allCurrencies:
            if(j["symbol"] == i):
                name = j["name"]
                image = "https://simpleswap.io"+j["image"]
                has_extra_id = j["has_extra_id"]
                extra_id = j["extra_id"]
        r.append({'name':name,'symbol':i,'image':image,"has_extra_id":has_extra_id,"extra_id":extra_id})
    return jsonify(r)

@app.route('/validatepair')
def validatepair():
    depositCurrency = request.args.get('depositcurrency',default=0)
    receiveCurrency = request.args.get('receivecurrency',default=0)
    fixed = request.args.get('fixed',default=0)
    if(0 in (depositCurrency,receiveCurrency,fixed)):
        return jsonify({'error': 'incomplete input'})
    if(fixed=="true" or fixed == True or fixed=="True"):
        values = fixedpairs.get(depositCurrency)
    else:
        values = pairs.get(depositCurrency)
    if(values is None):
        return jsonify({'error': 'Empty response'})
    if(receiveCurrency in values):
        return jsonify(True)
    else:
        return jsonify(False)

@app.route('/currencypair')
def currencyPair():
    symbol = request.args.get('symbol',default=0)
    fixed = request.args.get('fixed',default=0)
    if(0 in (symbol,fixed)):
        return jsonify({'error': 'incomplete input'})
    global pairs
    global allCurrencies
    if(pairs is None or allCurrencies is None or fixedpairs is None):
        return jsonify({"error": "empty pairs or allCurrencies"})
    print(allCurrencies,file=sys.stderr)
    if(fixed=='true' or fixed=='True' or fixed==True):
        a= fixedpairs.get(symbol)
    else:
        a = pairs.get(symbol)
    if(a is None):
        return jsonify({'error': 'Empty response'})
    a.sort()
    print(len(a),a,file=sys.stderr)
    r = []
    name = ''
    image = ''
    has_extra_id = ''
    extra_id = ''
    for i in a:
        for j in allCurrencies:
            if(j["symbol"] == i):
                name = j["name"]
                image = "https://simpleswap.io"+j["image"]
                has_extra_id = j["has_extra_id"]
                extra_id = j["extra_id"]
        r.append({'name':name,'symbol':i,'image':image,"has_extra_id":has_extra_id,"extra_id":extra_id})
    if(fixed=='true' or fixed=='True' or fixed==True):
        for i in r:
            if(i.get("symbol") == symbol):
                r.remove(i)
    return jsonify(r)

@app.route('/getrate')
def getRate():
    deposit = request.args.get('deposit',default=0)
    receive = request.args.get('receive',default=0)
    amount =  request.args.get('amount',default=0)
    fixed =  request.args.get('fixed',default=0)
    if(0 in (deposit,receive,amount,fixed)):
        return jsonify({"error": "incomplete input"})
    if(fixed=="true" or fixed=="True" or fixed is True):
        fixed = "true"
    else:
        fixed = ""
    print('https://api.simpleswap.io/v1/get_estimated?api_key={}&fixed={}&currency_from={}&currency_to={}&amount={}'.format(API_KEY,fixed,deposit,receive,amount),file=sys.stderr)
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_estimated?api_key={}&fixed={}&currency_from={}&currency_to={}&amount={}'.format(API_KEY,fixed,deposit,receive,amount))
    if(a.status_code<400 and a.status_code>=200):
        a = a.json()
    else:
        if(a.text=='Empty response'):
            return jsonify({"error": "Empty response"})
        else:
            return jsonify({"error": "404,500"})

    r = {'rate': a}
    print(r,file=sys.stderr)
    return jsonify(r)

@app.route('/validateaddress')
def validateaddress():
    symbol = request.args.get('symbol',default=0)
    address = request.args.get('address',default=0)
    validation_address = ''
    for i in allCurrencies:
        if(i['symbol'] == symbol):
            validation_address = i["validation_address"]
    if(validation_address is None):
        return {"valid": False}
    elif(validation_address==''):
        return {"valid": False}

    if(re.search(validation_address,address) is None):
        return {"valid":False}
    else:
        return {"valid": True}


@app.route('/validateextra')
def validateextra():
    symbol = request.args.get('symbol',default=0)
    extra = request.args.get('extra',default=0)
    validation_address = ''
    for i in allCurrencies:
        if(i['symbol'] == symbol):
            validation_extra = i["validation_extra"]
    if(validation_extra is None):
        return {"valid": False}
    elif(validation_extra==''):
        return {"valid": False}

    if(re.search(validation_extra,extra) is None):
        return {"valid":False}
    else:
        return {"valid": True}

@app.route('/validateid', methods=["POST"])
def validateid():
    data = request.get_json(force=True)
    id = data.get("id")
    if(id is None):
        return {"valid": False}

    id = re.sub('^[ ]*','',id)
    id = re.sub('[ ]*$','',id)
    if(len(id)<5 or len(id)>20):
        return {"valid": False}

    if(re.search("^[a-zA-Z0-9]*$",id) is None):
        return {"valid":False}
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_exchange?api_key={}&id={}'.format(API_KEY,id))
    if(a.status_code<400 and a.status_code>=200):
        return {"valid": True}
    else:
        return {"valid": False}

@app.route('/getminmax')
def getMinMax():
    deposit = request.args.get('deposit',default=0)
    receive = request.args.get('receive',default=0)
    fixed =  request.args.get('fixed',default=0)
    if(0 in (deposit,receive,fixed)):
        return jsonify({"error": "incomplete input"})
    if(fixed=="true" or fixed=="True" or fixed is True):
        fixed = "true"
    else:
        fixed = ""
    print('https://api.simpleswap.io/v1/get_ranges?api_key={}&fixed={}&currency_from={}&currency_to={}'.format(API_KEY,fixed,deposit,receive),file=sys.stderr)
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_ranges?api_key={}&fixed={}&currency_from={}&currency_to={}'.format(API_KEY,fixed,deposit,receive))
    if(a.status_code<400 and a.status_code>=200):
        a = a.json()
    else:
        if(a.text=='Empty response'):
            return jsonify({"error": "Empty response"})
        else:
            return jsonify({"error": "404,500"})

    min = a['min']
    max = a['max']
    try:
        min = float(min)
    except:
        min = None
    try:
        max = float(max)
    except:
        max = None
    r = {'min': min,'max': max}
    print(r,file=sys.stderr)
    return jsonify(r)

@app.route('/gettime',methods=["POST"])
def time():
    data = request.get_json(force=True)
    usertime = data.get("time")
    if(usertime is None):
        return jsonify({'error': 'Empty response'})
    timethen = datetime.datetime.strptime(usertime, '%Y-%m-%dT%H:%M:%S.%fZ')
    timenowstring = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    timenow = datetime.datetime.strptime(timenowstring, '%Y-%m-%dT%H:%M:%S.%fZ')
    c = timenow - timethen
    if(c.total_seconds()>(20*60)):
        return jsonify(-1)
    else:
        return jsonify((20*60) - int(c.total_seconds()))

@app.route('/sendcode',methods=["POST"])
def sendcode():
    try:
        data = request.get_json(force=True)
        username = data.get("username")
        domain = data.get("domain")
        if(None in (username,domain) or '' in (username,domain)):
            raise Exception()
    except Exception:
        return {'error': 'Error in data'}
    try:
        token = s.dumps(username, salt='email-confirm')
        msg = Message('Confirm Email', sender='hbutt877877@gmail.com', recipients=[username])
        link = url_for('login', token=token, _external=True)
        msg.body = 'Your link is {}?token={}'.format(domain,token)
        mail.send(msg)
        return {'success': 'code sent to email '} # + token    for testing
    except Exception:
        return {'error': 'Error in sending email'}

if __name__ == "__main__":
    tl.start()
    app.run()
