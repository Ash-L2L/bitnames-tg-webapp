const aesjs = require('aes-js');
const Buffer = require('buffer/').Buffer;
const canonicalize = require('canonicalize');
const crypto = require('crypto');
const eccrypto = require('@layertwolabs/eccrypto');
const path = require('path');
const pbkdf2 = require('pbkdf2');

let secret_ciphertext_hexstr =
    localStorage.getItem('secret_ciphertext_hexstr');
let cpubkey_hexstr =
    localStorage.getItem('cpubkey_hexstr');

let params = new URL(window.document.location).searchParams;
let request_base64url = params.get("tgWebAppStartParam");

// FIXME: remove
request_base64url = "eyJiaXRuYW1lX2hhc2giOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiY3BrX2hhc2giOiJhN2NhNTk2NmZjNzJiYTc4MTA4MTQ4MzhkZGFlNGM3MTQ5NjZhZjhlNzc3NGE1OWRlZTg0YzZmMmRkZTAxMjlmIiwic2lnbmVkX2JvZHkiOiIwM2QwNTlhM2Q0MTAxYzViZTM5OTJhNDI4MWJlZDU3YTNlMDMyZTcwMTNiYzFmMjJjMjY4ZTgwOWI2ZDZlOGFmOGQzOTI4ODAxMjAyNWNlYzFlN2NmY2YzYWFjMDRjNjE0Y2MxZWIzMzhjNGQ3NzY3ODhhYmNlYjUyYWY5YjYyYmMyZTEwYzM0MGM2MDczMDUyYzQ1MDY0YTk4YWM5N2M5YTYyZGYzMjc5MzE0NWI0ZTFlOTRkMThhODMyNzdiOGVhNGJmMzgwZjJhNzAxYmZmOWZkOWUyODcwYzcwYmUwMmViYjQ5MzE2YzFjYTAxNjM1MWZhZjE4NmZhZDE2ZGY1MWQ0M2M0ZDE2MTNkMTk0NDJjMGM0M2Y5ZjlhNDNiYmNjMmVmMDMyZDkwZDQxODBmZWVjOWE2Mzg1NzFlODM5ODdmZjU2MjljNDY2NmY3YmNhZjk4NDhhZDAwZWEwMzU1ZWVlOTlhOTQ5ZDYxMTIwYmQzYzcwM2QyNTE2Y2E5YzIxYWYzYzQyNDYwNmRiYzhmNmQ3ZTNkZjEwYTM0M2MyMjQ4ZGM5YmNkYzBhOGU2Yzc0NDBlMjdjY2ViYWY5OWRkYmI3NjliZWExYTE1NjRlNDc2NDVjOTMxOGFlMGUxMzhhOGM0NzcyZmVlNmIwZDQ2ZDI0YTZiNjk4YjIzNmViN2JiYmQzOTRkYTJjNmViOTg3ZGNiMjQwNTJjNGY2MmQ0NzVhNjMzMTg3OTU3ODc4Zjc2MWI0MjQ3MzJjYjAyZTQ3YjUzZDcxYWFjZDkxYmI1N2RiY2I1ZWVlMTFlNmEzZjU0YzUzNmFlZTA1YzM2NjU5MGE0NWFmZGJmNjZmYjA3YzE0ZTBhMjFmMDAzMmM3Mjk1ODkyYWU5ZjliNjhhOTFmYmZkMGE0YjMwNzhlMzkxOGE4MzJkMGQ1YjM5Nzg4ZThhYTEyMWRkYWUxNThkYmUzOWNkM2M3NzIwNjFiZDBjOTk5OWNiZDdkOTQ0MTI1NjIzNDI2NDM3ZTE4YzdiZTEyYzY3YzYxNjA3ZTZkMzc0YTgxZDg2MTZlMTY5NzYxOGRlMDkxZTc2NDZjNmE0ODBlMTJkNzU0MzRhYjVhMTExYWU2YjAwZDNkZDU1ZmExMmVlMDA1MGQ4NTJiNGYyNGY5MTIwZmIzYjkyMGRhYmQ3ZjRmNDlkOGI3OWVhZDBhNzhjIiwidmVyc2lvbiI6MX0";


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
    // compute salt for pbkdf2
    const hasher = crypto.createHash('sha256');
    hasher.update('bitnames-tg-webapp');
    const pbkdf2_salt = hasher.digest();

    //FIXME: no validation that this is actually hex
    const password = document.getElementById('password_input').value;
    const secret_ciphertext_hex =
        aesjs.utils.hex.toBytes(secret_ciphertext_hexstr);
    const aes_key = pbkdf2.pbkdf2Sync(password, pbkdf2_salt, 1, 256/8, 'sha512');
    const aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
    const secret_bytes = aes_ctr.decrypt(secret_ciphertext_hex);

    const stored_cpubkey_hexstr = cpubkey_hexstr;
    // check that the key was decrypted correctly
    const computed_cpubkey_hexstr =
        aesjs.utils.hex.fromBytes(
            eccrypto.getPublicCompressed(Buffer.from(secret_bytes))
        );
    console.assert(
        stored_cpubkey_hexstr === computed_cpubkey_hexstr,
        "Decrypting secret key failed"
    );

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

// returns the secret as a uint8array
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
            await cleanup();
            return await and_then(secret_bytes);
        }
    }

    // clear the prompt div
    async function cleanup() {
        const decrypt_div = document.getElementById('decrypt_div');
        decrypt_div.remove();
    }
}

// uses uint8arrays throughout
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
    const max_expiry_from_now =
        new Date(Date.now() + req_body.duration);
    const expiry = Math.min(limit_expiry, max_expiry_from_now);
    return new Date(expiry);
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
    let sig_buf = 
        await eccrypto.sign(
            Buffer.from(secret_bytes),
            canonical_resp_body_hash_buf
        );
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
    const encrypted_resp_buf = await encrypt(server_cpk_buf, canonical_resp_utf8_buf);
    return encrypted_resp_buf;
}

// prompt to sign response / cancel
async function prompt_sign(
    request,
    server_bitname,
    server_cpk_buf,
    session_id,
    expiry,
    secret_bytes
) {
    // expiry as a string
    const expiry_str = expiry.toString();
    
    let prompt_sign_div = document.createElement('div');
    prompt_sign_div.setAttribute('id', 'prompt_sign_div');
    prompt_sign_text = document.createElement('p');
    prompt_sign_text.setAttribute('id', 'prompt_sign_text');
    prompt_sign_text.textContent = `Sign in with ${server_bitname}?`;
    prompt_sign_text.textContent += `\nSession ID: ${session_id}`;
    prompt_sign_text.textContent += `\nExpiry: ${expiry_str}`;
    prompt_sign_div.appendChild(prompt_sign_text);

    let button_approve = document.createElement('button');
    let button_decline = document.createElement('button');
    button_approve.textContent = 'Approve';
    button_decline.textContent = 'Decline';
    prompt_sign_div.appendChild(button_approve);
    prompt_sign_div.appendChild(button_decline);
    button_approve.addEventListener("click", click_approve);
    button_decline.addEventListener("click", cleanup);
    document.body.appendChild(prompt_sign_div);
    
    // clear the prompt div
    async function cleanup() {
        const prompt_sign_div = document.getElementById('prompt_sign_div');
        prompt_sign_div.remove();
    }

    async function click_approve() {
        const encrypted_resp_buf =
        await sign_response(request, server_cpk_buf, expiry, secret_bytes);
        console.log("Encrypted OK!");
        console.log(encrypted_resp_buf);
        return await cleanup();
    }
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
        const encrypted_signed_req_body_bytes =
            new Uint8Array(aesjs.utils.hex.toBytes(request.signed_body));
        const signed_req_body_bytes =
            await decrypt(secret_bytes, encrypted_signed_req_body_bytes);
        let signed_req_body_hexstr =
            new TextDecoder().decode(signed_req_body_bytes);
        let signed_req_body = JSON.parse(signed_req_body_hexstr);
        console.assert(
            await validate_signed_req_body(signed_req_body),
            "Failed to validate signed request body"
        );
        const expiry = gen_expiry(signed_req_body.body);
        const server_bitname = signed_req_body.body.bitname;
        const server_cpk = signed_req_body.body.cpubkey;
        const server_cpk_buf =
            Buffer.from(aesjs.utils.hex.toBytes(server_cpk));
        const session_id = signed_req_body.body.session_id;
        await prompt_sign(
            request,
            server_bitname,
            server_cpk_buf,
            session_id,
            expiry,
            secret_bytes
        );
    }
    await prompt_decrypt_stored_secret(with_secret);
}

(async () => {
    await validate_request(request);
})();

/*
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
        await canonical_encrypt(Buffer.from(user_cpk_buf), signed_req_body);
    const encrypted_signed_req_body_hexstr =
        aesjs.utils.hex.fromBytes(encrypted_signed_req_body_buf);
    const user_cpk_hash_buf = Buffer.from(stored_cpubkey_hash());
    const user_cpk_hash_hexstr = aesjs.utils.hex.fromBytes(user_cpk_hash_buf);
    const req = {
        "version": 0x01,
        "bitname_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "cpk_hash": user_cpk_hash_hexstr,
        "signed_body": encrypted_signed_req_body_hexstr
    };
    return req;
}

// FIXME: remove
(async () => {
    const req = await gen_request();
    const canonical_req = canonicalize(req);
    const canonical_req_buf = Buffer.from(canonical_req, 'utf-8');
    const canonical_req_base64url = canonical_req_buf.toString('base64url');
    console.log("Request (base64url):");
    console.log(canonical_req_base64url);
})();
*/