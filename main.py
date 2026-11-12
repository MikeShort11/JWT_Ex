import json
import hashlib
import base64

BLOCK_SIZE = 64


def HMAC(pt:bytes | str, key:bytes | str) -> bytes:
    #encode key and plaintext if they are not bytes
    if isinstance(key, str):
        key = str.encode(key)
    if isinstance(pt, str):
        pt = str.encode(pt)

    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
        
    ipad = 0x36
    opad = 0x5C
    index = 32
    key = key.ljust(BLOCK_SIZE, b'\x00')
    
    ikey = bytes(b ^ 0x36 for b in key)
    okey = bytes(b ^ 0x5C for b in key)
        

    inner_hash = hashlib.sha256(ikey + pt).digest()
    outer_hash = hashlib.sha256(okey + inner_hash).digest()
    return outer_hash


# im expecting a dictonary for payload, and str for secret_key
def create_jwt(payload, secret_key, header=None):
    if header is None:
        header = {
            "alg":"HS256",
            "typ":"jwt"
        }
    if isinstance(secret_key, str):
        secret_key = str.encode(secret_key)

    json_head = json.dumps(header)
    json_pay = json.dumps(payload)

    h_and_p = base64.b64encode(str.encode(json_head) + b'.' + str.encode(json_pay))
    sig = HMAC(h_and_p, secret_key)
    jwt = h_and_p + sig
    return jwt
