
const aesjs = require('aes-js');
const eccrypto = require('@layertwolabs/eccrypto');
const crypto = require('crypto');
const pbkdf2 = require('pbkdf2');

const sign_in = require('./sign-in');

/*
let ctr_str = localStorage.getItem('ctr');
if(ctr_str===null){
    document.getElementById("show_storage").innerHTML = "STORAGE = NULL";
    let ctr = 0;
    localStorage.setItem('ctr', ctr.toString());
} else {
    document.getElementById("show_storage").innerHTML = `STORAGE = ${ctr_str}`;
    let ctr = parseInt(ctr_str);
    ctr++;
    localStorage.setItem('ctr', ctr.toString());
}
*/
window.Telegram.WebApp.ready();
//window.Telegram.WebApp.showAlert(ctr_str);

let secret_ciphertext_hexstr =
    localStorage.getItem('secret_ciphertext_hexstr');
if(secret_ciphertext_hexstr===null){
    // compute salt for pbkdf2
    const hasher = crypto.createHash('sha256');
    hasher.update('bitnames-tg-webapp');
    const pbkdf2_salt = hasher.digest();

    const secret_store = document.createElement('div');
    secret_store.setAttribute('id', 'secret_store');

    let secret_hex_input = document.createElement('input');
    secret_hex_input.setAttribute('id', 'secret_hex_input');
    secret_hex_input.setAttribute('type', 'text');
    let secret_hex_input_label = document.createElement('label');
    secret_hex_input_label.for = 'secret_hex_input';
    secret_hex_input_label.textContent = 'Secret key in hex encoding';
    secret_store.appendChild(secret_hex_input_label);
    secret_store.appendChild(secret_hex_input);
    secret_store.appendChild(document.createElement('br'));

    let password_input = document.createElement('input');
    password_input.setAttribute('id', 'password_input');
    password_input.setAttribute('type', 'text');
    let password_input_label = document.createElement('label');
    password_input_label.for = 'password_input';
    password_input_label.textContent = 'Password for encryption';
    secret_store.appendChild(password_input_label);
    secret_store.appendChild(password_input);
    secret_store.appendChild(document.createElement('br'));

    let button = document.createElement('button');
    button.textContent = 'Encrypt and store';
    secret_store.appendChild(button);
    button.addEventListener("click", encrypt_and_store);
    document.body.appendChild(secret_store);

    function encrypt_and_store() {
        //FIXME: no validation that this is actually hex
        let secret_store = document.getElementById('secret_store');
        let secret_hexstr = document.getElementById('secret_hex_input').value;
        let password = document.getElementById('password_input').value;
        let secret_hex = aesjs.utils.hex.toBytes(secret_hexstr);
        let cpubkey_hex = eccrypto.getPublicCompressed(Buffer.from(secret_hex));
        let aes_key = pbkdf2.pbkdf2Sync(password, pbkdf2_salt, 1, 256/8, 'sha512');
        let aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
        let secret_ciphertext = aes_ctr.encrypt(secret_hex);
        let secret_ciphertext_hexstr =
            aesjs.utils.hex.fromBytes(secret_ciphertext);
        localStorage.setItem(
            'secret_ciphertext_hexstr',
            secret_ciphertext_hexstr
        );
        let cpubkey_hexstr = aesjs.utils.hex.fromBytes(cpubkey_hex);
        localStorage.setItem('cpubkey_hexstr', cpubkey_hexstr);
        location.reload();
    }
} else {
    const err_div = document.createElement('div');
    err_div.setAttribute('id', 'err_div');
    err_text = document.createElement('p');
    err_text.setAttribute('id', 'err_text');
    let cpubkey_hexstr =
        localStorage.getItem('cpubkey_hexstr');
    err_text.textContent =
        `Secret exists in localStorage with cpubkey ${cpubkey_hexstr}`;
    err_div.appendChild(err_text);
    err_div.appendChild(document.createElement('br'));

    let clear_storage_button = document.createElement('button');
    clear_storage_button.textContent = 'Clear storage (UNSAFE)';
    err_div.appendChild(clear_storage_button);
    clear_storage_button.addEventListener("click", clear_storage);

    let sign_in_button = document.createElement('button');
    sign_in_button.textContent = 'Sign in with BitNames';
    err_div.appendChild(sign_in_button);
    sign_in_button.addEventListener("click", sign_in.sign_in);

    document.body.appendChild(err_div);

    function clear_storage() {
        localStorage.removeItem('secret_ciphertext_hexstr');
        localStorage.removeItem('cpubkey_hexstr');
        location.reload();
    }
}

/*
//FIXME: no validation that this is actually hex
let secret_hexstr = prompt("Enter your hex secret");
let password = prompt("Enter a password to encrypt the secret");
let secret_hex = aesjs.utils.hex.toBytes(secret_hexstr);
let aes_key = pbkdf2.pbkdf2Sync(password, pbkdf2_salt, 1, 256/8, 'sha512');
let aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
let secret_encrypted = aes_ctr.encrypt(secret_hex);

// decrypt secret
// need to re-instantiate aes_ctr
aes_ctr = new aesjs.ModeOfOperation.ctr(aes_key);
let secret_decrypted_hex = aes_ctr.decrypt(secret_encrypted);

if(secret_decrypted_hex == secret_hex){
    window.Telegram.WebApp.showAlert("Decrypted successfully");
} else {
    window.Telegram.WebApp.showAlert("Decryption failed");
}
*/

//let secret_encrypted =