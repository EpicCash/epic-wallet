from typing import Union
import base64
import json
import os

from coincurve import PublicKey, PrivateKey
from Crypto.Cipher import AES
import requests


# DEFAULT VALUES
api_url = f"http://127.0.0.1:3420/v3/owner"
auth_user = 'epic'
owner_api_secret_path = f"{os.environ['HOME']}/.epic/main/.owner_api_secret"
wallet_password = "your_password"

with open(owner_api_secret_path, 'r') as f:
    owner_api_secret = f.read()

basic_auth = (auth_user, owner_api_secret)


def parse_api_response(response: Union[dict, requests.Response]):
    """
    Parse EPIC API responses, handle different errors
    and extract the data from different response formats.
    """
    if isinstance(response, requests.Response):
        if response.status_code not in [200, 201]:
            if response.status_code == 401:
                raise SystemExit("Unauthorized to access API")
            else:
                raise SystemExit(f"Error: {response.status_code}, {response.reason}")
        try:
            response = response.json()
        except ValueError as e:
            raise SystemExit(f"Error while reading api response: '{str(e)}'\n"
                             f"Make sure your auth credentials are valid.")

    if "error" in response:
        raise SystemExit(f'{response["error"]}')

    elif "Err" in response:
        raise SystemExit(f'{response["result"]}')

    elif 'Ok' in response['result']:
        return response['result']['Ok']

    else:
        return response


def init_secure_api() -> str:
    """
    This is the first step in epic-wallet Secure API workflow
    Initialize process of computing encryption_key to encrypt payloads
    :return: encryption key
    """

    # Randomly created encryption key valid during the session
    secret_key = PrivateKey(os.urandom(32))

    # Prepare payload for the API call
    payload = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': "init_secure_api",
        'params': {'ecdh_pubkey': secret_key.public_key.format().hex()}
        }

    # POST your secret_key.public_key and receive new api_public_key
    response = requests.post(api_url, json=payload, auth=basic_auth)
    api_public_key_hex = parse_api_response(response)

    # Parse received api_public_key from hex to bytes
    api_public_key_bytes = PublicKey(bytes.fromhex(api_public_key_hex)).format()

    # Compute new encryption_key used for further encryption every api_call in this session
    encryption_key_ = PublicKey(api_public_key_bytes).multiply(secret_key.secret)

    # Format to hex and remove first 2 bits
    encryption_key_ = encryption_key_.format().hex()[2:]
    print(f"✅  Encryption key successfully generated")

    return encryption_key_


def encrypt(key: str, payload: dict) -> dict:
    """
    :param key: 32bit `secp256k1` ecdh encryption key computed via init_secure_api() func
    :param payload: json payload to encrypt
    :return: dict with base64 encoded AES-256-GMC encrypted payload and nonce as hex string

    Encrypt api_call JSON payload with:
     - encryption_key
     - 12bit nonce,
     - 16bit tag
    """
    nonce = os.urandom(12)
    message = json.dumps(payload).encode()
    aes_cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    encrypted_params = {'nonce': nonce.hex(), 'body_enc': base64.b64encode(ciphertext + tag).decode()}

    return encrypted_params


def decrypt(key: str, data: dict, nonce: bytes) -> str:
    """ Decrypt base64 encoded string
    :param key: 32bit `secp256k1` ecdh encryption key computed via init_secure_api() func
    :param data: encrypted message
    :param nonce: 12bit nonce as hex string
    :return: decoded string with JSON response
    """
    data = base64.b64decode(data)
    ciphertext = data[:-16]
    aesCipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce=nonce)
    plaintext = aesCipher.decrypt(ciphertext)

    return plaintext.decode()


def secure_api_call(key: str, method: str, params: dict):
    """
    Execute secure `owner_api` call, payload is encrypted
    :param key: 32bit secp256k1 ecdh encryption key computed via init_secure_api() func
    :param method: api call method name
    :param params: dict with api_call params
    :return: dict with decrypted data
    """

    payload = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': method,
        'params': params
        }

    # Encrypt payload with computed encryption key
    encrypted_payload = encrypt(key, payload)

    # Execute owner_api call with encrypted payload
    payload = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'encrypted_request_v3',
        'params': encrypted_payload
        }

    encrypted_response = requests.post(
        url=api_url,
        json=payload,
        auth=basic_auth
        )

    encrypted_response = parse_api_response(encrypted_response)

    # Decrypt response and return dict with response data
    nonce = bytes.fromhex(encrypted_response['nonce'])
    encrypted_response = encrypted_response['body_enc']

    decrypted_response = decrypt(
        encryption_key,
        encrypted_response,
        nonce
        )

    return parse_api_response(json.loads(decrypted_response))


def open_wallet(password, key) -> str:
    """
    This is the second step in epic-wallet API workflow
    Make an `open_wallet` API call, get authentication token and use it
    in all calls for this wallet instance during this session.
    """

    open_wallet_params = {
        'name': 'default',
        'password': password,
        }

    response = secure_api_call(
        key=key,
        method='open_wallet',
        params=open_wallet_params
        )

    print(f"✅  Secure token successfully generated")
    return response


"""
In the example below we will use defined functions to generate secure token 
and retrieve wallet balance. Different API endpoint will use different params
but the workflow will be the same.
"""

# Call `init_secure_api` API endpoint to initialize Secure API workflow
encryption_key = init_secure_api()

# Call `open_wallet` API endpoint to generate authentication token
token = open_wallet(
    password=wallet_password,
    key=encryption_key
    )

# Prepare `retrieve_summary_info` API call params
info_params = {
    "token": token,
    "refresh_from_node": True,
    "minimum_confirmations": 3
    }

# Call `retrieve_summary_info` endpoint and print the result
balance = secure_api_call(
    key=encryption_key,
    method='retrieve_summary_info',
    params=info_params)

print(balance)
