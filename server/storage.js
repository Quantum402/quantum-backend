const receipts = [];
const usedNonces = new Map(); // nonce -> expireAt (sec)

function rememberReceipt(r) { receipts.unshift(r); if (receipts.length > 500) receipts.pop(); }
function markNonce(nonce, expireAt) { usedNonces.set(nonce, expireAt); }
function seenNonce(nonce) {
  const exp = usedNonces.get(nonce);
  return !!exp && exp >= Math.floor(Date.now() / 1000);
}
function cleanupNonces() {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, exp] of usedNonces.entries()) if (exp < now) usedNonces.delete(k);
}

module.exports = { receipts, rememberReceipt, markNonce, seenNonce, cleanupNonces };

