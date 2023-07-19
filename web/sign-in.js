const aesjs = require('aes-js');
const canonicalize = require('canonicalize');
const crypto = require('crypto');
const eccrypto = require('@layertwolabs/eccrypto');
const path = require('path');
const pbkdf2 = require('pbkdf2');

let secret_ciphertext_hexstr =
    localStorage.getItem('secret_ciphertext_hexstr');
let cpubkey_hexstr =
    localStorage.getItem('cpubkey_hexstr');
let request_base64url =
    path.basename(window.location.pathname);
let request_bytes = new Uint8Array(Buffer.from(request_base64url, 'base64url'));
let request_hexstr =
    new TextDecoder().decode(request_bytes);
let request = JSON.parse(request_hexstr);

// compute the user's stored cpk hash
// returns a uint8array
function stored_cpubkey_hash() {
    console.assert(cpubkey_hexstr !== null, "failed to load cpubkey");
    let cpubkey_bytes =
        new Uint8Array(aesjs.utils.hex.toBytes(cpubkey_hexstr));
    let hasher = crypto.createHash('sha256');
    hasher.update(cpubkey_bytes);
    return new Uint8Array(hasher.digest());
}

async function decrypt_stored_secret() {
    //FIXME: no validation that this is actually hex
    const password = document.getElementById('password_input').value;
    const secret_ciphertext_hex =
        aesjs.utils.hex.toBytes(secret_ciphertext_hexstr);
    const aes_key = pbkdf2.pbkdf2Sync(password, pbkdf2_salt, 1, 256/8, 'sha512');
    const aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
    const secret_bytes = aes_ctr.decrypt(secret_ciphertext_hex);

    let decrypted_secret_ok = document.getElementById('decrypted_secret_ok');
    if(decrypted_secret_ok===null){
        decrypted_secret_ok_par = document.createElement('p');
        decrypted_secret_ok_par.setAttribute('id', 'decrypted_secret_ok');
        decrypt_div.appendChild(document.createElement('br'));
        decrypt_div.appendChild(decrypted_secret_ok_par);
    }
    decrypted_secret_ok_par.textContent = "Secret decrypted successfully";

    return secret_bytes;
}

async function prompt_decrypt_stored_secret(and_then) {
    if(secret_ciphertext_hexstr===null){
        const err_div = document.createElement('div');
        err_div.setAttribute('id', 'err_div');
        err_text = document.createElement('p');
        err_text.setAttribute('id', 'err_text');
        err_text.textContent = 'Failed to load secret ciphertext';
        err_div.appendChild(err_text);
        document.body.appendChild(err_div);
    } else {
        // compute salt for pbkdf2
        const hasher = crypto.createHash('sha256');
        hasher.update('bitnames-tg-webapp');
        const pbkdf2_salt = hasher.digest();
    
        const decrypt_div = document.createElement('div');
        decrypt_div.setAttribute('id', 'decrypt_div');
    
        let password_input = document.createElement('input');
        password_input.setAttribute('id', 'password_input');
        password_input.setAttribute('type', 'text');
        let password_input_label = document.createElement('label');
        password_input_label.for = 'password_input';
        password_input_label.textContent = 'Password for encryption';
        decrypt_div.appendChild(password_input_label);
        decrypt_div.appendChild(password_input);
        decrypt_div.appendChild(document.createElement('br'));
    
        let button = document.createElement('button');
        button.textContent = 'Decrypt secret key';
        decrypt_div.appendChild(button);
        button.addEventListener("click", click_decrypt_secret_key);
        document.body.appendChild(decrypt_div);
    
        async function click_decrypt_secret_key() {
            const secret_bytes = await decrypt_stored_secret();
            return await and_then(secret_bytes);
        }
    }
}

async function decrypt(secret_bytes, ciphertext_bytes) {
    const decrypt_args = {
        // For some reason, this fails if the IV is taken via subarray
        iv: Buffer.from(ciphertext_bytes.buffer.slice(33, 49)),
        ephemPublicKey: Buffer.from(ciphertext_bytes.subarray(0, 33)),
        ciphertext: Buffer.from(ciphertext_bytes.subarray(49, -32)),
        mac: Buffer.from(ciphertext_bytes.subarray(-32)),
    }
    let plaintext_buf =
        await eccrypto.decrypt(Buffer.from(secret_bytes), decrypt_args);
    return new Uint8Array(plaintext_buf);
}

function validate_req_body(req_body) {
    console.assert(
        req_body.version === 0x01,
        "Unsupported request body version number"
    );
    const session_expiry = new Date(req_body.session_expiry);
    console.assert(
        session_expiry < Date.now(),
        "Session is expired"
    );
    // FIXME: check session ID
    // FIXME: resolve bitname / cpk
}

async function validate_signed_req_body(signed_req_body) {
    const canonical_req_body_str = canonicalize(signed_req_body.body);
    const canonical_req_body_utf8_buf =
        Buffer.from(canonical_req_body_str, 'utf8');
    let hasher = crypto.createHash('sha256');
    hasher.update(canonical_req_body_utf8_buf);
    let canonical_req_body_hash_buf = hasher.digest();
    const req_cpk_hexstr = signed_req_body.body.cpubkey;
    const req_cpk_bytes =
        new Uint8Array(aesjs.utils.hex.toBytes(req_cpk_hexstr));
    const sig_hexstr = signed_req_body.signature;
    const sig_bytes =
        new Uint8Array(aesjs.utils.hex.toBytes(sig_hexstr));
    return await eccrypto.verify(
        Buffer.from(req_cpk_bytes),
        canonical_req_body_hash_buf,
        Buffer.from(sig_bytes)
    );
}

// generate a session expiry time from a request body
function gen_expiry(req_body) {
    // latest possible time for the expiry
    const limit_expiry = new Date(req_body.session_expiry);
    // current time + duration
    const max_expiry_from_now = Date.now() + req_body.duration;
    return Math.min(limit_expiry, max_expiry_from_now);

}

// compute the hash of a json object
// returns a buffer
function canonical_hash(json) {
    const canonical_json_str = canonicalize(json);
    const canonical_json_utf8_buf =
        Buffer.from(canonical_json_str, 'utf8');
    let hasher = crypto.createHash('sha256');
    hasher.update(canonical_json_utf8_buf);
    let canonical_json_hash_buf = hasher.digest();
    return canonical_json_hash_buf;
}

// encrypt message to the specified cpk
// returns a buffer
async function encrypt(cpk_buf, msg_buf) {
    const components = await eccrypto.encrypt(cpk_buf, msg_buf);
    const ciphertext_buf = Buffer.concat([
        components.ephemPublicKey,
        components.iv,
        components.ciphertext,
        components.mac
    ]);
    return ciphertext_buf;
}

// canonicalize json and encrypt to cpk
// returns a buffer
async function canonical_encrypt(cpk_buf, json) {
    const canonical_json_str = canonicalize(json);
    const canonical_json_utf8_buf =
        Buffer.from(canonical_json_str, 'utf8');
    const ciphertext_buf = await encrypt(cpk_buf, canonical_json_utf8_buf);
    return ciphertext_buf;
}

// generate a response and sign it
// returns a buffer
async function sign_response(
    request,
    server_cpk_buf,
    session_expiry,
    secret_bytes
) {
    let canonical_req_hash_buf = canonical_hash(request)
    let canonical_req_hash_hexstr =
        aesjs.utils.hex.fromBytes(canonical_req_hash_buf);
    let resp_body = {
        "request_hash": canonical_req_hash_hexstr,
        "session_expiry": session_expiry.getMilliseconds()
    };
    let canonical_resp_body_hash_buf = canonical_hash(resp_body);
    let canonical_resp_hash_hexstr =
        aesjs.utils.hex.fromBytes(canonical_resp_hash_buf);
    let sig_buf =
        await eccrypto.sign(secret_bytes, canonical_resp_hash_hexstr);
    let sig_hexstr =
        aesjs.utils.hex.fromBytes(sig_buf);
    let resp = {
        "version" : 0x01,
        "body" : resp_body,
        "signature" : sig_hexstr
    };
    const canonical_resp_str = canonicalize(resp);
    const canonical_resp_utf8_buf =
        Buffer.from(canonical_resp_str, 'utf8');
    // encrypt
    const encrypted_resp_buf = await encrypt(server_cpk_buf, session_expiry);
    return encrypted_resp_buf;
}

async function validate_request(request) {
    console.assert(
        request.version === 0x01,
        "Unsupported request version number"
    );
    // check bitname hash
    const cpk_hash_hexstr = request.cpk_hash;
    const cpk_hash =
        new Uint8Array(aesjs.utils.hex.toBytes(cpk_hash_hexstr));
    const stored_cpk_hash = stored_cpubkey_hash();
    console.assert(
        Buffer.compare(
            Buffer.from(stored_cpk_hash), Buffer.from(cpk_hash)) === 0,
            "Public key not found"
        );
    // validation steps once the secret is decrypted
    async function with_secret(secret_bytes) {
        const signed_req_body_bytes =
            await decrypt(secret_bytes, request.signed_body);
        let signed_req_body_hexstr =
            new TextDecoder().decode(signed_req_body_bytes);
        let signed_req_body = JSON.parse(signed_req_body_hexstr);
        console.assert(
            await validate_signed_req_body(signed_req_body),
            "Failed to validate signed request body"
        );
        const expiry = gen_expiry(signed_req_body.body);
        const server_cpk = signed_req_body.body.cpubkey;
        // FIXME: display bitname, session ID, expiry
        const encrypted_resp_buf =
            await sign_response(request, server_cpk, expiry, secret_bytes);
        console.log("Encrypted OK!");
        console.log(encrypted_resp_buf);
    }
    await prompt_decrypt_stored_secret(with_secret);
}

// FIXME: remove
async function gen_request() {
    const secret_buf = eccrypto.generatePrivate();
    const cpk_buf = eccrypto.getPublicCompressed(secret_buf);
    const cpk_hexstr = aesjs.utils.hex.fromBytes(cpk_buf);
    const req_body = {
        "version": 0x01,
        "bitname": "nyt.com",
        "cpubkey": cpk_hexstr,
        "session_id": "SESSION_ID",
        "session_expiry": 1690702632000,
        "duration": 1000 * 60 * 60 * 24,
    };
    const canonical_req_body_hash_buf = canonical_hash(req_body);
    const sig_buf = await eccrypto.sign(secret_buf, canonical_req_body_hash_buf);
    const sig_hexstr = aesjs.utils.hex.fromBytes(sig_buf);
    const signed_req_body = {
        "body": req_body,
        "signature": sig_hexstr,
    };
    let user_cpk_buf = new aesjs.utils.hex.toBytes(cpubkey_hexstr);
    const encrypted_signed_req_body_buf =
        await canonical_encrypt(user_cpk_buf, signed_req_body);
    const user_cpk_hash_buf = Buffer.from(stored_cpubkey_hash());
    const user_cpk_hash_hexstr = aesjs.utils.hex.fromBytes(user_cpk_hash_buf);
    const req = {
        "version": 0x01,
        "bitname_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "cpk_hash": user_cpk_hexstr,
        "signed_body": signed_req_body
    };
}
// FIXME: remove
const req = await gen_request();
const canonical_req = canonicalize(req);
const canonical_req_buf = Buffer.from(canonical_req, 'utf-8');
const canonical_req_base64url = canonical_req_buf.toString('base64url');
console.log("Request (base64url):");
console.log(canonical_req_base64url);