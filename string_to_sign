import base64
import hmac
from urllib import parse
from hashlib import sha256

def string_to_sign(string_to_sign, secret_access_key):
    h = hmac.new(secret_access_key, digestmod=sha256)
    h.update(string_to_sign.encode())
    sign = base64.b64encode(h.digest()).strip()
    signature = parse.quote_plus(sign)
    return signature

a = 'GET\n/iaas/\naccess_key_id=TUFFOOWVACNJDGSIYHJN&action=DescribeInstances&search_word=logstash&signature_method=HmacSHA256&signature_version=1&time_stamp=2018-02-22T14%3A12%3A15Z&version=1&zone=SHA'
b= b'lbCCkTB2kXj6fL2OOmNwMj8GWUrm0ywCvT22ZVWf'


if __name__ == '__main__':
    s=string_to_sign(a,b)
    print(s)
