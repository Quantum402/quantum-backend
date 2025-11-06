const nacl = require('tweetnacl');

const enc = new TextEncoder();
const nowSec = () => Math.floor(Date.now() / 1000);
const strToBytes = (s) => enc.encode(s);
const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const toB64 = (u8) => Buffer.from(u8).toString('base64');

function makeGatewayKeypair(seedB64) {
  if (seedB64) {
    const seed = fromB64(seedB64);
    if (seed.length !== 32) throw new Error('GATEWAY_SEED_BASE64 must be 32 bytes (base64)');
    return nacl.sign.keyPair.fromSeed(seed);
  }
  return nacl.sign.keyPair();
}

function signGateway(msgStr, secretKey) {
  const sig = nacl.sign.detached(strToBytes(msgStr), secretKey);
  return toB64(sig);
}

function verifyGateway(msgStr, sigB64, publicKeyU8) {
  return nacl.sign.detached.verify(strToBytes(msgStr), fromB64(sigB64), publicKeyU8);
}

module.exports = { nowSec, makeGatewayKeypair, signGateway, verifyGateway };
