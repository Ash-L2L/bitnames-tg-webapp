const aesjs = require('aes-js');
const crypto = require('crypto');
const pbkdf2 = require('pbkdf2');

let secret_ciphertext_hexstr =
    localStorage.getItem('secret_ciphertext_hexstr');
if(secret_ciphertext_hexstr===null){
    const err_div = document.createElement('div');
    err_div.setAttribute('id', 'err_div');
    err_text = document.createElement('p');
    err_text.setAttribute('id', 'err_text');
    err_text.textContent = 'Failed to load secret ciphertext';
    err_div.appendChild(err_text);
    document.body.appendChild(err_div);
}