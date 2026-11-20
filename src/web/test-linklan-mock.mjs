// node src/web/test-linklan-mock.mjs
// Drives LinklanCard against a mock GATT server that emulates the card firmware
// exactly as documented in protocol/linklan.md.  This exercises framing, the
// PSK handshake, AES-CCM and the SCARD/ES10 path without hardware.
import { hex, unhex, hmacSha256, aesccmEncrypt, aesccmDecrypt } from './crypto.js';
import { LinklanCard } from './transports.js';

const enc = new TextEncoder();
const concat = (...p) => { const n = p.reduce((a, x) => a + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };

// ---- protobuf helpers (server side, same tiny codec) --------------------- //
const vint = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return new Uint8Array(o); };
const fInt = (f, v, always = false) => (!v && !always ? new Uint8Array() : concat(vint(f << 3), vint(v)));
const fBytes = (f, v) => (!v || !v.length ? new Uint8Array() : concat(vint((f << 3) | 2), vint(v.length), v));
const pDecode = (data) => {
  const out = {}; let i = 0;
  const rv = () => { let s = 0, r = 0, b; do { b = data[i++]; r |= (b & 0x7f) << s; s += 7; } while (b & 0x80); return r; };
  while (i < data.length) {
    const key = rv(), f = key >>> 3, w = key & 7;
    if (w === 0) out[f] = rv();
    else if (w === 2) { const l = rv(); out[f] = data.slice(i, i + l); i += l; }
    else if (w === 1) { out[f] = data.slice(i, i + 8); i += 8; }
    else if (w === 5) { out[f] = data.slice(i, i + 4); i += 4; }
  }
  return out;
};

// ---- mock card ----------------------------------------------------------- //
const PSK = await hmacSha256(enc.encode('000000'), enc.encode('SecurePbChannel'));
const EID = '89000000000000000000000000000001';

class MockCard {
  constructor() { this.buf = new Uint8Array(); this.expect = 0; this.key = null; this.counter = 0; this.frames = []; }
  // returns a response frame (protobuf bytes) or null
  async handle(payload) {
    const m = pDecode(payload);
    const cmd = m[1];
    if (this.key === null) {
      if (cmd === 3) {                                     // security / auth
        const sd = pDecode(m[2]);
        const secProto = pDecode(sd[3]);          // SecurityProtocol{ 2: SecurityAuth }
        const authMsg = pDecode(secProto[2]);
        const cliRandom = authMsg[1], proof = authMsg[2];
        const mac = await this.mac(cliRandom);
        const expect = await hmacSha256(mac.slice(0, 16), cliRandom, new Uint8Array(32));
        if (hex(expect) !== hex(proof)) return this.securityError(5);
        this.key = mac.slice(16, 32);
        this.nonce = crypto.getRandomValues(new Uint8Array(12));
        this.aad = crypto.getRandomValues(new Uint8Array(16));
        this.counter = 0;
        const cfgAuth = await hmacSha256(mac.slice(0, 16), this.nonce, this.aad, new Uint8Array(32));
        const proto = concat(fInt(1, 1), fBytes(3, concat(fBytes(1, this.nonce), fBytes(2, this.aad), fBytes(3, cfgAuth))));
        return fBytes(3, proto);            // { 3: SecurityProtocol }   (real card)
      }
      // plaintext: challenge for getDeviceInfo
      this.devRandom = crypto.getRandomValues(new Uint8Array(16));
      const proto = fBytes(2, concat(fBytes(1, this.devRandom)));
      return concat(fInt(1, m[1]), fBytes(5, proto));
    }
    // encrypted
    const sd = pDecode(m[2]);
    const counter = sd[1];
    if (counter !== this.counter + 1) return this.securityError(5);
    this.counter = counter;
    const nonce = Uint8Array.from(this.nonce);
    const n = ((nonce[8] << 24) | (nonce[9] << 16) | (nonce[10] << 8) | nonce[11]) + counter;
    nonce[8] = (n >>> 24) & 0xff; nonce[9] = (n >>> 16) & 0xff; nonce[10] = (n >>> 8) & 0xff; nonce[11] = n & 0xff;
    let inner;
    try {
      inner = await aesccmDecrypt(this.key, nonce, this.aad, sd[2]);
    } catch (e) {
      console.log('MOCK decrypt failed; counter', counter, 'key', hex(this.key), 'nonce', hex(nonce), 'aad', hex(this.aad));
      throw e;
    }

    const im = pDecode(inner);
    if (globalThis.BLPA_DEBUG) console.log('MOCK inner', hex(inner), 'cmd', im[1]);
    let reply;
    if (im[1] === 2) reply = this.scard(pDecode(im[2]));
    else if (im[1] === 0) reply = concat(fInt(1, 0), fBytes(3, this.deviceInfo()));
    else reply = concat(fInt(1, im[1]), fBytes(3, new Uint8Array()));
    if (globalThis.BLPA_DEBUG) console.log('MOCK reply len', reply.length, hex(reply).slice(0, 40));
    const ct = await aesccmEncrypt(this.key, nonce, this.aad, reply);
    return concat(fInt(1, counter, true), fBytes(2, ct));   // bare SecurityData{id, enc}
  }
  mac(cliRandom) { return hmacSha256(PSK, enc.encode('SecurePbChannel'), this.devRandom, cliRandom); }
  deviceInfo() {
    const str = (f, v) => fBytes(f, enc.encode(v));
    return concat(str(1, 'Linksfield'), str(2, '<imei>'), str(3, '<sn>'),
                  str(4, 'BLE-eSIM v0'), fInt(6, 1));
  }
  scard(req) {
    const cmd = req[1];
    if (cmd === 1) return concat(fInt(1, 1), fInt(2, 0));                 // openChannel ok
    const ta = pDecode(req[4]);
    const unzz = (v) => (v >> 1) ^ -(v & 1);
    const ins = unzz(ta[3]);
    let body;
    if (ins === 0xe2) {
      const data = unhex(new TextDecoder().decode(ta[7]));
      const tag = data[0] << 8 | data[1];
      if (tag === 0xbf3e) body = concat(unhex('bf3e125a10'), unhex(EID), unhex('9000'));
      else if (tag === 0xbf2d) body = concat(unhex('bf2d02a000'), unhex('9000'));
      else body = concat(unhex('bf31038001'), new Uint8Array([0]), unhex('9000'));
    } else body = unhex('9000');
    const payload = body.slice(0, -2), sw = body.slice(-2);
    const taRsp = concat(fInt(1, sw[0] << 1), fInt(2, sw[1] << 1), fBytes(3, payload));
    return concat(fInt(1, 2), fInt(2, 0), fBytes(4, taRsp));
  }
  securityError(code) { return fInt(5, code); }                     // bare SecurityData{error}
}

// ---- fake GATT ----------------------------------------------------------- //
function makeDevice(card) {
  const listeners = [];
  const notifyValue = (bytes) => {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (const l of listeners) l({ target: { value: dv } });
  };
  const write = {
    async writeValueWithResponse(frame) {
      const data = new Uint8Array(frame.buffer ?? frame, frame.byteOffset ?? 0, frame.byteLength ?? frame.length);
      if (!card.expect) card.expect = (data[0] << 8) | data[1];
      card.buf = concat(card.buf, data);
      if (card.buf.length < card.expect + 2) return;
      const payload = card.buf.slice(2, 2 + card.expect);
      card.buf = new Uint8Array(); card.expect = 0;
      const rsp = await card.handle(payload);
      if (rsp && rsp.length) {
        const out = concat(new Uint8Array([rsp.length >> 8, rsp.length & 0xff]), rsp);
        setTimeout(() => notifyValue(out), 0);
      }
    },
  };
  const notify = {
    async startNotifications() {},
    addEventListener: (_ev, cb) => listeners.push(cb),
  };
  return {
    name: 'BLE-eSIM-00000000',
    gatt: {
      connected: true,
      async connect() { return this; },
      disconnect() {},
      async getPrimaryService() {
        return { async getCharacteristic(uuid) { return uuid === '6e400002-b5a3-f393-e0a9-e50e24dcca9e' ? write : notify; } };
      },
    },
  };
}

// ---- test ---------------------------------------------------------------- //
const fake = new MockCard();
const device = makeDevice(fake);
const card = new LinklanCard({ password: '000000' });
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`${name.padEnd(12)} ${ok ? 'OK' : 'FAIL'}  ${extra}`); if (!ok) failures++; };

try {
  await card.connect(device);
  check('handshake', true);
  const eid = await card.eid();
  check('eid', eid === EID, eid);
  const profiles = await card.profiles();
  check('profiles', profiles.length === 0);
  check('enable', await card.enable('8900000000000000001'));
} catch (e) {
  check('transport', false, e.message);
  console.log(e.stack.split('\n').slice(0, 6).join('\n'));
}
process.exit(failures ? 1 : 0);
