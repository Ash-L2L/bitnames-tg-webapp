
const aesjs = require('aes-js');
const crypto = require('crypto');
const pbkdf2 = require('pbkdf2');

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
window.Telegram.WebApp.ready();
window.Telegram.WebApp.showAlert(ctr_str);

// compute salt for pbkdf2
const hasher = crypto.createHash('sha256');
hasher.update('bitnames-tg-webapp');
const pbkdf2_salt = hasher.digest();

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

//let secret_encrypted = 