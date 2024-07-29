import requests
import json
import os
import hashlib
import time
from flask import Flask, render_template, request
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

api = os.getenv('KEY')

DEFAULTS = {'url': 'http://example.com'}

api_url = 'https://www.virustotal.com/vtapi/v2/url/report'

headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent": "gzip, My Python requests library example client or username"
}

proxy_list = {
    'http': 'http://username:password@proxyserver:proxyport',
    'https': 'https://username:password@proxyserver:proxyport'
}

@app.route('/', methods=['GET', 'POST'])
def home():
    url = ""
    if request.method == 'POST':
        url = request.form['inputURL']
    
    allurls = [url]
    if allurls == ['']:
        allurls = [DEFAULTS['url']]
        
    resultVT = []
    for i in allurls:
        time.sleep(5)
        response = findUrlatVT(i)
        resultVT.append(response)
    resultVTjson = json.dumps(resultVT)
    print(resultVT)
    
    return render_template('home.html', resultVT=resultVT, resultVTjson=resultVTjson)

def findUrlatVT(url):
    print(url)
    params = {'apikey': api, 'resource': url}
    try:
        response = requests.get(api_url, params=params, headers=headers, verify=False)
    except requests.ConnectionError as e:
        return e
    
    try:
        json_response = response.json()
        positives = json_response['positives']
        total = json_response['total']
        permalink = json_response['permalink']
    except KeyError:
        positives = 'n'
        total = 'a'
        permalink = ''
    
    try:
        Symantec_response = json_response['scans']['Symantec']['detected']
        Symantec_result = json_response['scans']['Symantec']['result']
        Symantec_update = json_response['scans']['Symantec']['update']
    except KeyError:
        Symantec_response = '-'
        Symantec_result = '-'
        Symantec_update = '-'

    try:
        Trendmicro_response = json_response['scans']['TrendMicro']['detected']
    except KeyError:
        Trendmicro_response = '-'

    try:
        Sophos_response = json_response['scans']['Sophos']['detected']
    except KeyError:
        Sophos_response = '-'

    try:
        McAfee_response = json_response['scans']['McAfee']['detected']
    except KeyError:
        McAfee_response = '-'
    
    return url, positives, total, Symantec_response, Symantec_result, Symantec_update, Trendmicro_response, Sophos_response, McAfee_response, permalink

if __name__ == '__main__':
    app.run(port=5001, debug=True)
