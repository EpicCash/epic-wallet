/* Sample Code for connecting to the V3 Secure API via Node
 *
 * With thanks to xiaojay of Niffler Wallet:
 * https://github.com/epicfans/Niffler/blob/gw3/src/shared/walletv3.js
 *
 */

let password = ""; // your wallet pass
let port = "3420"; // :13420 = default floonet port, :3420 default mainnet port
let api_secret = ""; //`cat ~/.epic/main/.api_secret` or `cat ~/.epic/floo/.api_secret`

const jayson = require('jayson/promise');
const crypto = require('crypto');



const client = jayson.client.http('http://epic:'+ api_secret +'@127.0.0.1:' + port + '/v3/owner');

// Demo implementation of using `aes-256-gcm` with node.js's `crypto` lib.
const aes256gcm = (shared_secret) => {
	const ALGO = 'aes-256-gcm';

	// encrypt returns base64-encoded ciphertext
	const encrypt = (str, nonce) => {
		let key = Buffer.from(shared_secret, 'hex')
		const cipher = crypto.createCipheriv(ALGO, key, nonce)
		const enc = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()])
		const tag = cipher.getAuthTag()
		return Buffer.concat([enc, tag]).toString('base64')
	};

	// decrypt decodes base64-encoded ciphertext into a utf8-encoded string
	const decrypt = (enc, nonce) => {
		//key,nonce is all buffer type; data is base64-encoded string
		let key = Buffer.from(shared_secret, 'hex')
		const data_ = Buffer.from(enc, 'base64')
		const decipher = crypto.createDecipheriv(ALGO, key, nonce)
		const len = data_.length
		const tag = data_.slice(len-16, len)
		const text = data_.slice(0, len-16)
		decipher.setAuthTag(tag)
		const dec = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
		return dec
	};

	return {
		encrypt,
		decrypt,
	};
};

class JSONRequestEncrypted {
	constructor(id, method, params) {
		this.jsonrpc = '2.0'
		this.method = method
		this.id = id
		this.params = params
	}

	async send(key){
		const aesCipher = aes256gcm(key);
		const nonce = new Buffer.from(crypto.randomBytes(12));
		let enc = aesCipher.encrypt(JSON.stringify(this), nonce);
		console.log("Encrypted: " + enc)
		let params = {
			'nonce': nonce.toString('hex'),
			'body_enc': enc,
		}
		let response = await client.request('encrypted_request_v3', params);

		if (response.err) {
			throw response.err
		}

		const nonce2 = Buffer.from(response.result.Ok.nonce, 'hex');
		const data = Buffer.from(response.result.Ok.body_enc, 'base64');

		let dec = aesCipher.decrypt(data, nonce2)
		return dec
	}
}

async function initSecure() {
	let ecdh = crypto.createECDH('secp256k1')
	ecdh.generateKeys()
	let publicKey = ecdh.getPublicKey('hex', 'compressed')
	const params = {
		'ecdh_pubkey': publicKey
	}
	let response = await client.request('init_secure_api', params);
	if (response.err) {
		throw response.err
	}

	return ecdh.computeSecret(response.result.Ok, 'hex', 'hex')
}

async function main() {
	let shared_key = await initSecure();

	let response = await new JSONRequestEncrypted(1, 'open_wallet', {
		"name": null,
		"password": password,
	}).send(shared_key);

  console.log(response);
	let token = JSON.parse(response).result.Ok;
	/* get data from a export with command ./epic-wallet export_proof -i 17 testproof.txt */
	let info_response = await new JSONRequestEncrypted(2, 'verify_payment_proof', {
			"token": token,
			"proof": {
			  "amount": "232400000",
			  "excess": "08a551b3b06fcac53fc719c08640a216839133438d313e7c7e5c0ce0b31c3056e1",
			  "recipient_address": "qjrfkoysp4mulzbxiyhsvik5t4yb4636hpuoxqveylg5dovm4nosx7id",//Receiver Address (Onion V3)
			  "recipient_sig": "ab6c4f6434a1f66d7106aa830d4784de428105754465ba864199690764c910d4ff425aefda04c16934311a9414eb9baf3da18b77b55e9c25ee15fdf998419a0d",
			  "sender_address": "v7yeumerch3svoeqomn2likjrucfhg2m3moucb5bcohxktmcbzmw2bqd",//Sender Address (Onion V3)
			  "sender_sig": "aa29e81034ae8a0764e3a20e3c3cdee37b5d86ba42e3cbc391c00517c5529c8f23b8cd1369582b72852a76815b1131b7b217ae06b4e35d40f13c451a1cd74400"
			}
	}).send(shared_key)

	console.log("Info Response: ", info_response);

}



main();
