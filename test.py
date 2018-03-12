from datetime import datetime

#now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
#print(now)
#%Y%m%dT%H%M%SZ
#YYYY-MM-DDThh:mm:ssZ

import base64
import hmac
from urllib import parse
from hashlib import sha256

string_to_sign = 'GET\n/iaas/\naccess_key_id=TUFFOOWVACNJDGSIYHJN&action=DescribeInstances&search_word=logstash&signature_method=HmacSHA256&signature_version=1&time_stamp=2018-02-22T14%3A12%3A15Z&version=1&zone=SHA'
secret_access_key = b'lbCCkTB2kXj6fL2OOmNwMj8GWUrm0ywCvT22ZVWf'
h = hmac.new(secret_access_key, digestmod=sha256)
h.update(string_to_sign.encode())
sign = base64.b64encode(h.digest()).strip()
signature = parse.quote_plus(sign)
print(signature)

#time_stamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
general_parameter = {"zone":"SHA","access_key_id":"TUFFOOWVACNJDGSIYHJN","version":1,"signature_method":"HmacSHA256","signature_version":1,"time_stamp":datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}

def string_to_sign(string_to_sign, secret_access_key):
    h = hmac.new(secret_access_key, digestmod=sha256)
    h.update(string_to_sign.encode())
    sign = base64.b64encode(h.digest()).strip()
    signature = parse.quote_plus(sign)
    return signature

string_to_sign = 'GET\n/iaas/\naccess_key_id=TUFFOOWVACNJDGSIYHJN&action=DescribeInstances&search_word=logstash&signature_method=HmacSHA256&signature_version=1&time_stamp=2018-02-22T14%3A12%3A15Z&version=1&zone=SHA'
secret_access_key = b'lbCCkTB2kXj6fL2OOmNwMj8GWUrm0ywCvT22ZVWf'

s=string_to_sign(string_to_sign,secret_access_key)
print(s)
