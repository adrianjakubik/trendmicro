import base64
import jwt
import hashlib
import requests
from urllib3.exceptions import InsecureRequestWarning
import time
import json

# disable security warnings
# see https://stackoverflow.com/questions/15445981/how-do-i-disable-the-security-certificate-check-in-python-requests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# see https://automation.trendmicro.com/apex-central/Guides/API-Demo-Project-Pyt
def create_checksum(http_method, raw_url, headers, request_body):
    string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body    
    base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
    return base64_string    
    
def create_jwt_token(appication_id, api_key, http_method, raw_url, headers, request_body,
                     iat=time.time(), algorithm='HS256', version='V1'):
    checksum = create_checksum(http_method, raw_url, headers, request_body)
    payload = {'appid': appication_id,
               'iat': iat,
               'version': version,
               'checksum': checksum}
    token = jwt.encode(payload, api_key, algorithm=algorithm).decode('utf-8')
    return token

# https://stackoverflow.com/questions/3605866/hide-password-when-checking-config-file-in-git
try:
    from credentials import *
except ImportError:
    pass

# see https://automation.trendmicro.com/apex-central/api#tag/Logs
productAgentAPIPath = '/WebApp/api/v1/Logs/device_access_control'

canonicalRequestHeaders = ''
useQueryString="?output_format=CEF&page_token=0&since_time=1654239106"
useRequestBody = ''

jwt_token = create_jwt_token(use_application_id, use_api_key, 'GET',
                              productAgentAPIPath + useQueryString,
                              canonicalRequestHeaders, useRequestBody, iat=time.time())
headers = {'Authorization': 'Bearer ' + jwt_token}

r = requests.get(use_url_base + productAgentAPIPath + useQueryString, headers=headers, data=useRequestBody, verify=False)
parsed = (r.json())

#https://devqa.io/python-parse-json/
print("Found entries:" + json.dumps(parsed['Data']['Count'], indent=4, sort_keys=True))
print("\n")
print(json.dumps(parsed['Data']['Logs'], indent=4, sort_keys=True))
