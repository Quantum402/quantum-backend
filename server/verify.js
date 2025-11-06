const nacl = require('tweetnacl');
const bs58 = require('bs58');
const { ethers } = require('ethers');

const enc = new TextEncoder();
const bytes = (s) => enc.encode(s);

async function verifySolanaMessage({ message, signatureBase64, account }) {
  try {
    const pub = bs58.decode(account);
    const sig = Buffer.from(signatureBase64, 'base64');
    return nacl.sign.detached.verify(bytes(message), sig, pub);
  } catch {
    return false;
  }
}

async function verifyEvmMessage({ message, signatureHex, account }) {
  try {
    const recovered1 = ethers.verifyMessage(message, signatureHex);
    if (recovered1.toLowerCase() === account.toLowerCase()) return true;
  } catch {}
  try {
    const recovered2 = ethers.verifyMessage(ethers.getBytes(message), signatureHex);
    return recovered2.toLowerCase() === account.toLowerCase();
  } catch {
    return false;
  }
}

module.exports = { verifySolanaMessage, verifyEvmMessage };
