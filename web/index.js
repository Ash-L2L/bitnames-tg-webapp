
const aesjs = require('aes-js');
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
//FIXME: no validation that this is actually hex
let secret_hexstr = window.prompt("Enter your hex secret");
let password = window.prompt("Enter a password to encrypt the secret");
let secret_hex = aesjs.utils.hex.toBytes(secret_hexstr);
//let secret_encrypted = 