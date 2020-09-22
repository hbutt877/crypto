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

app = Flask(__name__)
CORS(app)

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

@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        amount = request.form["amount"]
        address=request.form["address"]
        depositCurrency = request.form['depositCurrency']
        receiveCurrency = request.form['receiveCurrency']
        print(depositCurrency,receiveCurrency,file=sys.stderr)
        # new_amount = requests.get('https://api.simpleswap.io/v1/get_estimated?api_key=b72d5b0f-9505-4063-9104-5d7a1c314562&fixed=false&currency_from=btc&currency_to=eth&amount='+amount).text
        r = requests.post('https://api.simpleswap.io/v1/create_exchange?api_key='+API_KEY,json={"fixed": "", "currency_from":depositCurrency,"currency_to":receiveCurrency,"address_to":address,"amount":amount}).json()
        if('code' in r):
            if(r['code']==400):
                return redirect(url_for("exchange", id="Address not valid"))
        else:
            id = r['id']
            return redirect(url_for("exchange", id=id))
    else:
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

        # http = urllib3.PoolManager()
        # r = http.request('GET','https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY)
        # r = json.loads(r.data.decode('utf-8'))
        # pairs = http.request('GET','https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY))
        # pairs = json.loads(pairs.data.decode('utf-8'))
        depositCurrency = []
        tmp = pairs.keys()
        tmp = list(tmp)
        tmp.sort()
        # print(len(tmp),tmp,file=sys.stderr)
        name = ''
        image = ''
        for i in tmp:
            # t = {}
            # t['symbol'] = i['symbol']
            # t['name'] = i['name']
            for j in allCurrencies:
                if(j["symbol"] == i):
                    name = j["name"]
                    image = "https://simpleswap.io"+j["image"]
            depositCurrency.append({'symbol':i,'name':name,'image':image})
        return jsonify(depositCurrency)
        # return render_template("login.html",depositCurrency=depositCurrency)

@app.route('/getcurrencies')
def getCurrencies():
    fixed = request.args.get('fixed',default=0)
    if(fixed==0):
        return jsonify({'error': 'incomplete input'})
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
    # a = requests.get('https://api.simpleswap.io/v1/get_pairs?api_key={}&fixed=&symbol={}'.format(API_KEY,symbol)).json()
    # print(symbol,file=sys.stderr)
    # print(r,file=sys.stderr)
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


@app.route("/createexchange", methods=["POST"])
def createexchange():
    data = request.get_json(force=True)
    print(data,file=sys.stderr)
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
    print(r.status_code,file=sys.stderr)
    if(r.status_code<400 and r.status_code>=200):
        id = r.json()['id']
        return jsonify({'id': id})
    else:
        return jsonify({'id':-1})



@app.route('/getexchange')
def getexchange():
    id = request.args.get('id',default=0)
    if(id==0):
        return jsonify({'error': 'invalid id'})
#Remove dummy before deployment
#Remove dummy before deployment
#Remove dummy before deployment
    if(id=="dummy"):
        a = {"address_from":"34NjfWgoeH41M4MNdmi8LdSsRMG9qTcDpY","address_to":"GBH4TZYZ4IRCPO44CBOLFUHULU2WGALXTAVESQA6432MBJMABBB4GIYI","amount_from":"1","amount_to":"125258.30224260","currency_from":"btc","currency_to":"xlm","expected_amount":"1","extra_id_from":None,"extra_id_to":"abcd","id":"LKuAYqAUwMM","status":"finished","timestamp":"2020-09-13T19:23:24.767Z","tx_from":"input hash example","tx_to":"output hash example","type":"floating","updated_at":"2020-09-14T19:24:18.247Z"}
        return jsonify(a)
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_exchange?api_key={}&id={}'.format(API_KEY,id))
    if(a.status_code<400 and a.status_code>=200):
        a = a.json()
        a.pop('currencies', None)
    else:
        return jsonify({'error': 'may be invalid id'})
    return a



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
    timethen = datetime.datetime.strptime(usertime, '%Y-%m-%dT%H:%M:%S.%fZ')
    timenowstring = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    timenow = datetime.datetime.strptime(timenowstring, '%Y-%m-%dT%H:%M:%S.%fZ')
    c = timenow - timethen
    if(c.total_seconds()>(20*60)):
        return jsonify(-1)
    else:
        return jsonify((20*60) - int(c.total_seconds()))

if __name__ == "__main__":
    tl.start()
    app.run(debug=False)
