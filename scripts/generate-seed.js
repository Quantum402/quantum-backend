const nacl = require('tweetnacl');
console.log(Buffer.from(nacl.randomBytes(32)).toString('base64'));
