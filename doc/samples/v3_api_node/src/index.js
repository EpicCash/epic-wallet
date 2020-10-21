/* Sample Code for connecting to the V3 Secure API via Node
 *
 * With thanks to xiaojay of Niffler Wallet:
 * https://github.com/grinfans/Niffler/blob/gw3/src/shared/walletv3.js
 *
 */

// TODO setup Authorization

// const jayson = require('jayson/promise');
const crypto = require('crypto');

const jaysonBrowserClient = require('jayson/lib/client/browser');
const fetch = require('node-fetch');
const addr_send_dest = "http://0.0.0.0:13515";
const amount = 10 * 100000000;
const username = "epic";
const password = "";

const callServer = function(request, callback) {
    const options = {
        method: 'POST',
        body: request,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic <epic:`cat cat ~/.epic/floo/.api_secret`>'
        }
    };

    // console.log(options);

    fetch('http://localhost:13420/v3/owner', options)
        .then(function(res) { return res.text(); })
        .then(function(text) {return callback(text);});
};

const client = jaysonBrowserClient(callServer, {
    // other options go here
});

async function main() {
    let ecdh = crypto.createECDH('secp256k1');
    ecdh.generateKeys();
    let publickey = ecdh.getPublicKey('hex', 'compressed');

    const params = {
        'jsonrpc': '2.0',
        'method': 'init_secure_api',
        'params':{
            'ecdh_pubkey': publickey
        },
		    'id': 1
    };

    client.request(params, function(result){
        let response = JSON.parse(result);

        let shared_key = ecdh.computeSecret(response.result.Ok, 'hex', 'hex');
        // console.log('shared_key', shared_key);

        open_wallet(shared_key);
    });
}

async function open_wallet(shared_key) {
    let response = new JSONRequestEncrypted(1, 'open_wallet', {
		    "name": username,
		    "password": password,
	  }).send(shared_key, false, callback_open_wallet);
}


// Demo implementation of using `aes-256-gcm` with node.js's `crypto` lib.
const aes256gcm = (shared_secret) => {
	  const ALGO = 'aes-256-gcm';

	  // encrypt returns base64-encoded ciphertext
	  const encrypt = (str, nonce) => {
		    let key = Buffer.from(shared_secret, 'hex');
		    const cipher = crypto.createCipheriv(ALGO, key, nonce);
		    const enc = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()]);
		    const tag = cipher.getAuthTag();
		    return Buffer.concat([enc, tag]).toString('base64');
	  };

	  // decrypt decodes base64-encoded ciphertext into a utf8-encoded string
	  const decrypt = (enc, nonce) => {
		    //key,nonce is all buffer type; data is base64-encoded string
		    let key = Buffer.from(shared_secret, 'hex');
		    const data_ = Buffer.from(enc, 'base64');
		    const decipher = crypto.createDecipheriv(ALGO, key, nonce);
		    const len = data_.length;
		    const tag = data_.slice(len-16, len);
		    const text = data_.slice(0, len-16);
		    decipher.setAuthTag(tag);
		    const dec = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
		    return dec;
	  };

	  return {
		    encrypt,
		    decrypt,
	  };
};

class JSONRequestEncrypted {
	  constructor(id, method, params) {
		    this.jsonrpc = '2.0';
		    this.method = method;
		    this.id = id;
		    this.params = params;
	  }

	  async send(key, token, callback_fn){
		    const aesCipher = aes256gcm(key);
		    const nonce = new Buffer.from(crypto.randomBytes(12));
		    let enc = aesCipher.encrypt(JSON.stringify(this), nonce);
		    // console.log("Encrypted: " + enc)
		    let params = {
			      'nonce': nonce.toString('hex'),
			      'body_enc': enc,
		    };

        const body = {
            'jsonrpc': '2.0',
            'method': 'encrypted_request_v3',
            params,
		        'id': 1
        };

		    client.request(body, function(res) {callback_fn(aesCipher, token, key, res);});
	  }
}


function sleep(ms) {
	  return new Promise(resolve => setTimeout(resolve, ms));
}

function decrypt_result(result, aesCipher) {
    let response = JSON.parse(result);
    const nonce2 = Buffer.from(response.result.Ok.nonce, 'hex');
    const data = Buffer.from(response.result.Ok.body_enc, 'base64');

    let dec = aesCipher.decrypt(data, nonce2);

    return dec;
}

async function callback_retrieve_summary_info(aesCipher, token, shared_key, result) {
    let dec = decrypt_result(result, aesCipher);
    let info_wallet = JSON.parse(dec).result.Ok;
		console.log("info wallet: ", info_wallet);
    await sleep(2000);

    let _txs_response = new JSONRequestEncrypted(2, 'init_send_tx',{
        "token": token,
        "args": {
            "src_acct_name": null,
            "amount": amount,
            "minimum_confirmations": 10,
            "max_outputs": 500,
            "num_change_outputs": 1,
            "selection_strategy_is_use_all": false,
            "target_slate_version": null,
            "payment_proof_recipient_address": null,
            "ttl_blocks": null,
            "send_args": {"method":"http",
                          "dest": addr_send_dest,
                          "finalize":true,
                          "post_tx":true,
                          "fluff":false}
        }
    }).send(shared_key, token, callback_init_send_tx);
}


function callback_open_wallet(aesCipher, token, shared_key, result) {
    let dec = decrypt_result(result, aesCipher);
    token = JSON.parse(dec).result.Ok;
    console.log('token: '+ token);
		let info_response = new JSONRequestEncrypted(1, 'retrieve_summary_info', {
			  "token": token,
			  "refresh_from_node": true,
			  "minimum_confirmations": 1,
		}).send(shared_key, token, callback_retrieve_summary_info);
}

async function callback_init_send_tx(aesCipher, token, shared_key, result) {
    let dec = decrypt_result(result, aesCipher);
    let txs_response = JSON.parse(dec);
		console.log("Send tx: ", txs_response);
    await sleep(2000);

    let info_response = new JSONRequestEncrypted(3, 'close_wallet', {
			  "name": username,
		}).send(shared_key, token, callback_close_wallet);
}

async function callback_close_wallet(aesCipher, token, shared_key, result) {
    let dec = decrypt_result(result, aesCipher);
    let res = JSON.parse(dec);
		console.log("Close: ", res);
    await sleep(2000);
}

main();
