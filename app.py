from flask import Flask, redirect, url_for, render_template, request,jsonify
import requests
import sys
import time
import urllib3
import json
from timeloop import Timeloop
from datetime import timedelta
import re

app = Flask(__name__)

API_KEY = 'b72d5b0f-9505-4063-9104-5d7a1c314562'
pairs = None
allCurrencies = None

tl = Timeloop()

@tl.job(interval=timedelta(seconds=3600))
def sample_job():
    global allCurrencies
    session = requests.Session()
    session.trust_env = False
    allCurrencies = session.get('https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY).json()

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
        global allCurrencies
        a = time.time()
        session = requests.Session()
        session.trust_env = False
        allCurrencies = session.get('https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY).json()
        pairs = session.get('https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY)).json()
        # http = urllib3.PoolManager()
        # r = http.request('GET','https://api.simpleswap.io/v1/get_all_currencies?api_key='+API_KEY)
        # r = json.loads(r.data.decode('utf-8'))
        # pairs = http.request('GET','https://api.simpleswap.io/v1/get_all_pairs?api_key={}&fixed='.format(API_KEY))
        # pairs = json.loads(pairs.data.decode('utf-8'))
        print(time.time()-a,file=sys.stderr)
        depositCurrency = []
        tmp = pairs.keys()
        tmp = list(tmp)
        tmp.sort()
        # print(len(tmp),tmp,file=sys.stderr)
        name = ''
        image = ''
        a = time.time()
        for i in tmp:
            # t = {}
            # t['symbol'] = i['symbol']
            # t['name'] = i['name']
            for j in allCurrencies:
                if(j["symbol"] == i):
                    name = j["name"]
                    image = "https://simpleswap.io"+j["image"]
            depositCurrency.append({'symbol':i,'name':name,'image':image})
        print(time.time()-a,file=sys.stderr)
        return jsonify(depositCurrency)
        # return render_template("login.html",depositCurrency=depositCurrency)

@app.route("/exchange")
def exchange():
    r = request.args.get('id',0)
    print(r,file=sys.stderr)
    return "id = " + r

@app.route('/currencypair')
def currencyPair():
    symbol = request.args.get('symbol',default=0)
    # a = requests.get('https://api.simpleswap.io/v1/get_pairs?api_key={}&fixed=&symbol={}'.format(API_KEY,symbol)).json()
    # print(symbol,file=sys.stderr)
    # print(r,file=sys.stderr)
    global pairs
    global allCurrencies
    if(pairs is None or allCurrencies is None):
        return jsonify({"error": "empty pairs or allCurrencies"})
    print(allCurrencies,file=sys.stderr)
    a = pairs[symbol]
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
    return jsonify(r)

@app.route('/getrate')
def getRate():
    deposit = request.args.get('deposit',default=0)
    receive = request.args.get('receive',default=0)
    amount =  request.args.get('amount',default=0)
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_estimated?api_key={}&fixed=&currency_from={}&currency_to={}&amount={}'.format(API_KEY,deposit,receive,amount)).json()
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
    session = requests.Session()
    session.trust_env = False
    a = session.get('https://api.simpleswap.io/v1/get_ranges?api_key={}&fixed=&currency_from={}&currency_to={}'.format(API_KEY,deposit,receive)).json()
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

if __name__ == "__main__":
    tl.start()
    app.run(debug=False)
