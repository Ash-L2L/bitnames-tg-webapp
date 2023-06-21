const aesjs = require('aes-js');
const crypto = require('crypto');
const eccrypto = require('@layertwolabs/eccrypto');
const path = require('path');
const pbkdf2 = require('pbkdf2');

let secret_ciphertext_hexstr =
    localStorage.getItem('secret_ciphertext_hexstr');
let ciphertext_hexstr =
    path.basename(window.location.pathname);
let ciphertext_hex = new Uint8Array(aesjs.utils.hex.toBytes(ciphertext_hexstr));

/*
const ciphertext_div = document.createElement('div');
ciphertext_div.setAttribute('id', 'ciphertext_div');
ciphertext_text = document.createElement('p');
ciphertext_text.setAttribute('id', 'ciphertext_text');
ciphertext_text.textContent = `Ciphertext hex: ${ciphertext_hexstr}`;
ciphertext_div.appendChild(ciphertext_text);
document.body.appendChild(ciphertext_div);
*/

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
    button.addEventListener("click", decrypt_and_show);
    document.body.appendChild(decrypt_div);

    async function decrypt_and_show() {
        //FIXME: no validation that this is actually hex
        let password = document.getElementById('password_input').value;
        let secret_ciphertext_hex =
            aesjs.utils.hex.toBytes(secret_ciphertext_hexstr);
        let aes_key = pbkdf2.pbkdf2Sync(password, pbkdf2_salt, 1, 256/8, 'sha512');
        let aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
        let secret_hex = aes_ctr.decrypt(secret_ciphertext_hex);

        /*
        let secret_hexstr = aesjs.utils.hex.fromBytes(secret_hex);
        let show_secret = document.getElementById('show_secret');
        if(show_secret===null){
            show_secret = document.createElement('p');
            show_secret.setAttribute('id', 'show_secret');
            decrypt_div.appendChild(document.createElement('br'));
            decrypt_div.appendChild(show_secret);
        }
        show_secret.textContent = `Secret: ${secret_hexstr}`;
        */

        let decrypted_secret_ok = document.getElementById('decrypted_secret_ok');
        if(decrypted_secret_ok===null){
            decrypted_secret_ok_par = document.createElement('p');
            decrypted_secret_ok_par.setAttribute('id', 'decrypted_secret_ok');
            decrypt_div.appendChild(document.createElement('br'));
            decrypt_div.appendChild(decrypted_secret_ok_par);
        }
        decrypted_secret_ok_par.textContent = "Secret decrypted successfully";

        let decrypt_args = {
            // For some reason, this fails if the IV is taken via subarray
            iv: Buffer.from(ciphertext_hex.buffer.slice(33, 49)),
            ephemPublicKey: Buffer.from(ciphertext_hex.subarray(0, 33)),
            ciphertext: Buffer.from(ciphertext_hex.subarray(49, -32)),
            mac: Buffer.from(ciphertext_hex.subarray(-32)),
        }

        await eccrypto.decrypt(Buffer.from(secret_hex), decrypt_args)
            .then(function(plaintext_hex) {
                let show_plaintext = document.getElementById('show_plaintext');
                if(show_plaintext===null){
                    show_plaintext = document.createElement('p');
                    show_plaintext.setAttribute('id', 'show_plaintext');
                    decrypt_div.appendChild(document.createElement('br'));
                    decrypt_div.appendChild(show_plaintext);
                }
                let plaintext_hexstr =
                    aesjs.utils.hex.fromBytes(plaintext_hex);
                show_plaintext.textContent =
                    `Plaintext hex: ${plaintext_hexstr}`;
            });

    }
}