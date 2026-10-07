// WireGuard key pair in the browser: X25519 (RFC 7748) with BigInt, no dependencies.
// The private key is random bytes from crypto.getRandomValues and never leaves the page
// unless the user downloads/copies the config.
(function (global) {
  "use strict";
  const P = (1n << 255n) - 19n;
  const A24 = 121665n;

  function mod(a) { a %= P; return a < 0n ? a + P : a; }
  function pow(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
  function cswap(swap, a, b) { return swap ? [b, a] : [a, b]; }

  function clamp(bytes) {
    const k = Uint8Array.from(bytes);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    return k;
  }

  function scalarMult(k, u) {
    let x1 = u, x2 = 1n, z2 = 0n, x3 = u, z3 = 1n, swap = 0;
    for (let t = 254; t >= 0; t--) {
      const kt = (k[t >> 3] >> (t & 7)) & 1;
      swap ^= kt;
      [x2, x3] = cswap(swap, x2, x3);
      [z2, z3] = cswap(swap, z2, z3);
      swap = kt;
      const A = mod(x2 + z2), AA = A * A % P;
      const B = mod(x2 - z2), BB = B * B % P;
      const E = mod(AA - BB);
      const C = mod(x3 + z3), D = mod(x3 - z3);
      const DA = D * A % P, CB = C * B % P;
      x3 = mod((DA + CB) ** 2n);
      z3 = x1 * mod((DA - CB) ** 2n) % P;
      x2 = AA * BB % P;
      z2 = E * mod(AA + A24 * E) % P;
    }
    [x2, x3] = cswap(swap, x2, x3);
    [z2, z3] = cswap(swap, z2, z3);
    return x2 * pow(z2, P - 2n) % P;
  }

  function toBytesLE(n) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) { out[i] = Number(n & 255n); n >>= 8n; }
    return out;
  }

  function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
  function unb64(text) { return Uint8Array.from(atob(text), c => c.charCodeAt(0)); }

  function publicFromPrivate(privateB64) {
    const priv = unb64(privateB64);
    if (priv.length !== 32) throw new Error("Private key must be 32 bytes");
    return b64(toBytesLE(scalarMult(clamp(priv), 9n)));
  }

  function generateKeyPair() {
    const priv = new Uint8Array(32);
    crypto.getRandomValues(priv);
    const privateKey = b64(clamp(priv));
    return { privateKey, publicKey: publicFromPrivate(privateKey) };
  }

  global.WGKeys = { generateKeyPair, publicFromPrivate };
})(window);
