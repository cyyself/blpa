// Three BLE eSIM transports for Web Bluetooth (and Node, with a fake GATT).
import { hex, unhex, hmacSha256, aesccmEncrypt, aesccmDecrypt, tripleDesEcb, sum16 } from './crypto.js';
import * as tlv from './tlv.js';

const NUS = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
const NUS_WRITE = '6e400002-b5a3-f393-e0a9-e50e24dcca9e';
const NUS_NOTIFY = '6e400003-b5a3-f393-e0a9-e50e24dcca9e';
const AE30 = '0000ae30-0000-1000-8000-00805f9b34fb';
const ISDR = 'A0000005591010FFFFFFFF8900000100';

const enc = new TextEncoder();

// ------------------------------------------------------------- protobuf ---- //
const vint = (n) => { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return new Uint8Array(o); };
const pInt = (f, v, always = false) => (!v && !always ? new Uint8Array() : concat(vint(f << 3), vint(v)));
const pBytes = (f, v) => (!v || !v.length ? new Uint8Array() : concat(vint((f << 3) | 2), vint(v.length), v));
const pStr = (f, s) => pBytes(f, enc.encode(s));
function concat(...p) { const n = p.reduce((a, x) => a + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; }
function pDecode(data) {
  const out = {};
  let i = 0;
  const rv = () => { let shift = 0, r = 0, b; do { b = data[i++]; r |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80); return r; };
  while (i < data.length) {
    const key = rv(); const f = key >>> 3, w = key & 7;
    if (w === 0) { out[f] = rv(); }
    else if (w === 2) { const l = rv(); out[f] = data.slice(i, i + l); i += l; }
    else if (w === 1) { out[f] = data.slice(i, i + 8); i += 8; }
    else if (w === 5) { out[f] = data.slice(i, i + 4); i += 4; }
    else throw new Error('bad wire ' + w);
  }
  return out;
}
const zz = (v) => (v >= 0 ? v << 1 : ((-v) << 1) - 1);
const unzz = (v) => (v >> 1) ^ -(v & 1);

// ------------------------------------------------------------ base card ---- //
class BaseCard {
  constructor(opts = {}) { this.opts = opts; this.device = null; this.server = null; }
  static get label() { return 'card'; }
  async disconnect() { if (this.device?.gatt?.connected) this.device.gatt.disconnect(); }
  async storeData() { throw new Error('not implemented'); }
  async eid() {
    const v = tlv.find(await this.storeData(tlv.cmdEid()), 0xbf3e, 0x5a);
    if (!v) throw new Error('no EID in response');
    return tlv.bcd(v);
  }
  async profiles() { return tlv.parseProfiles(await this.storeData(tlv.cmdProfiles())); }
  async _op(cmd, tag, name) {
    const code = tlv.resultCode(await this.storeData(cmd), tag);
    if (code !== 0) throw new Error(`${name} failed (code ${code})`);
    return true;
  }
  enable(iccid) { return this._op(tlv.cmdEnable(iccid), 0xbf31, 'enable'); }
  disable(iccid) { return this._op(tlv.cmdDisable(iccid), 0xbf32, 'disable'); }
  delete(iccid) { return this._op(tlv.cmdDelete(iccid), 0xbf33, 'delete'); }
  nickname(iccid, nick) { return this._op(tlv.cmdNickname(iccid, nick), 0xbf29, 'nickname'); }
  async info() { return { kind: this.constructor.label, name: this.device?.name ?? '', eid: await this.eid() }; }
}

// ---------------------------------------------------------------- Linklan -- //
export class LinklanCard extends BaseCard {
  static get label() { return 'linklan'; }
  static filters() { return [{ namePrefix: 'BLE-eSIM' }]; }

  constructor(opts) {
    super(opts);
    this.psk = null;
    this.key = null; this.nonce = null; this.aad = null; this.counter = 0;
    this.buf = new Uint8Array(); this.expect = 0; this.resolve = null;
  }
  async setCredentials({ pskHex, password } = {}) {
    if (pskHex) this.psk = unhex(pskHex);
    else if (password) this.psk = await hmacSha256(enc.encode(password), enc.encode('SecurePbChannel'));
    else this.psk = await hmacSha256(enc.encode('Linksfield@Esim#2025'), enc.encode('SecurePbChannel'));
  }
  async connect(device) {
    this.device = device ?? this.device;
    if (!this.psk) await this.setCredentials(this.opts);
    this.server = await this.device.gatt.connect();
    const svc = await this.server.getPrimaryService(NUS);
    this.write = await svc.getCharacteristic(NUS_WRITE);
    this.notify = await svc.getCharacteristic(NUS_NOTIFY);
    await this.notify.startNotifications();
    this.notify.addEventListener('characteristicvaluechanged', (e) => this._onNotify(e.target.value));
    await this._request(0, pInt(1, 1, true));
    this.channel = 4;
    await this._openChannel();
  }
  _onNotify(dv) {
    const data = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
    if (!this.buf.length) this.expect = (data[0] << 8) | data[1];
    this.buf = concat(this.buf, data);
    if (this.expect && this.buf.length >= this.expect + 2) {
      const rsp = this.buf.slice(2, 2 + this.expect);
      this.buf = new Uint8Array();
      const done = this.resolve; this.resolve = null;
      if (done) done(rsp);
    }
  }
  async _send(payload) {
    const frame = concat(new Uint8Array([payload.length >> 8, payload.length & 0xff]), payload);
    const p = new Promise((res) => { this.resolve = res; });
    // Web Bluetooth exposes no MTU, so start optimistic and shrink on failure:
    // Chrome throws on a write larger than ATT MTU-3.
    let chunk = this.chunk ?? 244;
    for (let i = 0; i < frame.length;) {
      const size = Math.min(chunk, frame.length - i);
      try {
        await this._writeChunk(frame.slice(i, i + size));
        i += size;
      } catch (e) {
        if (chunk <= 20) throw e;
        chunk = Math.max(20, Math.floor(chunk / 2));
        this.chunk = chunk;
      }
    }
    return await p;
  }
  async _writeChunk(bytes) {
    if (this.writeProps?.writeWithResponse !== false) {
      try {
        await this.write.writeValueWithResponse(bytes);
        this.writeProps = { writeWithResponse: true };
        return;
      } catch (e) {
        if (!this.write.writeValueWithoutResponse) throw e;
        this.writeProps = { writeWithResponse: false };
      }
    }
    await this.write.writeValueWithoutResponse(bytes);
  }
  _frame(cmd, payload = new Uint8Array()) { return concat(pInt(1, cmd, true), pBytes(2, payload)); }
  async _classify(rsp) {
    // Real card (verified against the hardware and the Python client):
    //   device challenge : { 1: cmd, 5: SecurityProtocol{AUTH} }
    //   auth answer      : { 3: SecurityProtocol{UPDATE, config} }
    //   encrypted reply  : SecurityData{ 1: id, 2: ciphertext }   (bare, no envelope)
    //   protocol error   : SecurityData{ 5: code }
    // Some stacks nest the SecurityData inside { cmd = 3, request = 2 }, so both
    // shapes are accepted.  Field 3 is ambiguous (DeviceInfo also lives there).
    let m;
    try { m = pDecode(rsp); } catch { return ['plain', rsp]; }

    if (m[2] instanceof Uint8Array) {
      // A bare SecurityData whose counter happens to be 3 looks exactly like a
      // nested {cmd=3, request} envelope, so try the nested reading first and
      // fall back to "field 2 is the ciphertext".
      if (m[1] === 3 && m[3] === undefined && m[5] === undefined) {
        try {
          const sd = pDecode(m[2]);
          if (sd[2] instanceof Uint8Array) return ['enc', sd[2]];
          if (sd[3] instanceof Uint8Array && sd[3].length) return ['protocol', sd[3]];
          if (typeof sd[5] === 'number') return ['error', sd[5]];
        } catch { /* not a nested envelope */ }
      }
      return ['enc', m[2]];
    }
    if (m[5] instanceof Uint8Array && m[5].length) return ['protocol', m[5]];
    if (typeof m[5] === 'number') return ['error', m[5]];
    if (m[3] instanceof Uint8Array && m[3].length) {
      try {
        const inner = pDecode(m[3]);
        if (!(inner[1] instanceof Uint8Array)) return ['protocol', m[3]];
      } catch { /* not a SecurityProtocol */ }
    }
    return ['plain', rsp];
  }
  async _request(cmd, payload = new Uint8Array()) {
    const inner = this._frame(cmd, payload);
    if (!this.key) {
      const rsp = await this._send(inner);
      const [kind, value] = await this._classify(rsp);
      if (globalThis.BLPA_DEBUG) console.log('CLIENT plaintext-request kind', kind, 'rsp', hex(rsp));
      if (kind !== 'protocol') throw new Error('linklan: security required');
      await this._authenticate(value);
      return this._request(cmd, payload);
    }
    this.counter += 1;
    const nonce = Uint8Array.from(this.nonce);
    const n = ((nonce[8] << 24) | (nonce[9] << 16) | (nonce[10] << 8) | nonce[11]) + this.counter;
    nonce[8] = (n >>> 24) & 0xff; nonce[9] = (n >>> 16) & 0xff; nonce[10] = (n >>> 8) & 0xff; nonce[11] = n & 0xff;
    if (globalThis.BLPA_DEBUG) console.log('CLIENT key', hex(this.key), 'nonce', hex(nonce), 'aad', hex(this.aad), 'ctr', this.counter, 'inner', hex(inner));
    const ct = await aesccmEncrypt(this.key, nonce, this.aad, inner);
    const rsp = await this._send(this._frame(3, concat(pInt(1, this.counter, true), pBytes(2, ct))));
    const [kind, value] = await this._classify(rsp);
    if (globalThis.BLPA_DEBUG) console.log('CLIENT enc-request ctr', this.counter, 'kind', kind, 'rsp', hex(rsp));
    if (kind === 'enc') return aesccmDecrypt(this.key, nonce, this.aad, value);
    if (kind === 'protocol') { this.key = null; await this._authenticate(value); return this._request(cmd, payload); }
    throw new Error('linklan: ' + kind + ' ' + value);
  }
  async _authenticate(proto) {
    const p = pDecode(proto);
    const type = typeof p[1] === 'number' ? p[1] : 0;
    if (type === 1 || p[3]) {                       // SecurityProtocol.UPDATE
      const cfg = pDecode(p[3]);
      this.key = this.pendingKey;
      this.nonce = cfg[1]; this.aad = cfg[2]; this.counter = 0;
      return;
    }
    const auth = p[2];                              // SecurityProtocol.AUTH
    if (!auth) throw new Error('linklan: challenge without auth');
    const devRandom = pDecode(auth)[1];
    const cliRandom = crypto.getRandomValues(new Uint8Array(16));
    const mac = await hmacSha256(this.psk, enc.encode('SecurePbChannel'), devRandom, cliRandom);
    const proof = await hmacSha256(mac.slice(0, 16), cliRandom, new Uint8Array(32));
    this.pendingKey = mac.slice(16, 32);
    // SecurityProtocol{ auth = 2: SecurityAuth{ random = 1, auth = 2 } } — the
    // extra field-2 wrapper is what the card expects (see the Python client).
    const authMsg = pBytes(2, concat(pBytes(1, cliRandom), pBytes(2, proof)));
    for (let id = 0; id < 6; id++) {
      const rsp = await this._send(this._frame(3, concat(pInt(1, id, true), pBytes(3, authMsg))));
      const [kind, value] = await this._classify(rsp);
      if (globalThis.BLPA_DEBUG) console.log('CLIENT auth id', id, 'kind', kind, 'rsp', hex(rsp));
      if (kind === 'protocol') { await this._authenticate(value); return; }
      if (kind === 'error') continue;
    }
    throw new Error('linklan: authentication failed (wrong PSK/password)');
  }
  async _openChannel() {
    const body = concat(pInt(1, 1, true), pBytes(2, concat(pStr(1, ISDR), pInt(2, 0))));
    await this._request(2, body);
  }
  async transmit(apdu, maxApdu = 255) {
    const data = apdu.slice(5, 5 + apdu[4]);
    const ta = concat(pInt(1, zz(this.channel)), pInt(2, zz(apdu[0])), pInt(3, zz(apdu[1])),
      pInt(4, zz(apdu[2])), pInt(5, zz(apdu[3])), pInt(6, zz(data.length)), pStr(7, hex(data).toUpperCase()));
    const rsp = await this._request(2, concat(pInt(1, 3, true), pBytes(4, ta)));
    const taRsp = pDecode(rsp)[4];
    if (!taRsp) throw new Error('linklan: no transmitApdu response');
    const r = pDecode(taRsp);
    return concat(r[3] ?? new Uint8Array(), new Uint8Array([unzz(r[1]) & 0xff, unzz(r[2]) & 0xff]));
  }
  async storeData(cmd) {
    const block = 240;
    let pos = 0, idx = 0;
    for (;;) {
      const rest = cmd.slice(pos);
      const more = rest.length > block;
      const chunk = more ? rest.slice(0, block) : rest;
      const p1 = more ? 0x11 : 0x91;
      let rsp = await this.transmit(concat(new Uint8Array([0x80, 0xe2, p1, idx, chunk.length]), chunk));
      while (rsp[rsp.length - 2] === 0x61) rsp = await this.transmit(new Uint8Array([0x80, 0xc0, 0x00, 0x00, rsp[rsp.length - 1]]));
      const sw = rsp.slice(-2);
      if (more) {
        if (hex(sw) !== '9000') throw new Error('linklan: STORE DATA ' + hex(sw));
        pos += block; idx += 1; continue;
      }
      if (hex(sw) !== '9000' && sw[0] !== 0x91) throw new Error('linklan: SW ' + hex(sw));
      return rsp.slice(0, -2);
    }
  }
  async info() {
    const rsp = await this._request(0, pInt(1, 1, true));
    const info = pDecode(rsp)[3];
    const f = info ? pDecode(info) : {};
    const txt = (k) => (f[k] ? new TextDecoder().decode(f[k]) : '');
    return { kind: 'linklan', name: this.device.name, eid: await this.eid(),
             vendor: txt(1), imei: txt(2), sn: txt(3), model: txt(4) };
  }
}

// ------------------------------------------------------------------ 9eSIM -- //
export class Esim9Card extends BaseCard {
  static get label() { return '9esim'; }
  static filters() { return [{ namePrefix: '9eSIM' }, { namePrefix: 'esim_writer' }]; }

  constructor(opts) {
    super(opts);
    this.buf = new Uint8Array(); this.packets = []; this.resolve = null; this.counter = 0;
  }
  static defaultPassword(name) { return [...name.trim().slice(-6)].reverse().join(''); }
  static authKey(name, password) {
    const pass = password ?? Esim9Card.defaultPassword(name);
    const hexPass = /^[0-9a-fA-F]{6}$/.test(pass.trim()) ? pass.trim().toUpperCase() : crc24(pass);
    const base = name.slice(-2) + hexPass;
    return unhex(base.repeat(3) + '00000000');
  }
  async connect(device) {
    this.device = device ?? this.device;
    this.key = Esim9Card.authKey(this.device.name, this.opts.password);
    this.server = await this.device.gatt.connect();
    const svc = await this.server.getPrimaryService(NUS);
    this.write = await svc.getCharacteristic(NUS_WRITE);
    this.notify = await svc.getCharacteristic(NUS_NOTIFY);
    await this.notify.startNotifications();
    this.notify.addEventListener('characteristicvaluechanged', (e) => this._onNotify(e.target.value));
    await this._handshake();
  }
  _onNotify(dv) {
    const data = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
    this.packets.push(data);
    this.buf = concat(this.buf, data.slice(1));
    if (data[0] & 0x20) { const r = this.resolve; this.resolve = null; if (r) r([this.packets, this.buf]); }
  }
  async _wait(timeout = 8000) {
    const p = new Promise((res, rej) => {
      this.resolve = res; this.packets = []; this.buf = new Uint8Array();
      setTimeout(() => { if (this.resolve) { this.resolve = null; rej(new Error('9esim: timeout')); } }, timeout);
    });
    return p;
  }
  async _write(payload, chunk = 100) {
    for (let i = 0; i < payload.length; i += chunk) {
      const part = payload.slice(i, i + chunk);
      const last = i + chunk >= payload.length;
      const header = (last ? 0x20 : 0x00) | ((i / chunk) & 0x1f);
      await this.write.writeValueWithoutResponse(concat(new Uint8Array([header]), part));
    }
  }
  async _handshake() {
    const [packets] = await this._wait();
    const greet = packets[0];
    if (!greet || greet.length < 17 || greet[0] !== 0xe0) throw new Error('9esim: no greeting');
    const plain = tripleDesEcb(this.key, greet.slice(1, 17), true);
    let counter = (plain[7] | (plain[8] << 8)) & 0xffff;
    counter = (counter + 1) & 0xffff;
    plain[7] = counter & 0xff; plain[8] = (counter >> 8) & 0xff;
    await this.write.writeValueWithoutResponse(concat(new Uint8Array([0xe0]), tripleDesEcb(this.key, plain, false)));
    const [ack] = await this._wait();
    const sw = ack[0] ? hex(ack[0].slice(1, 3)) : '';
    if (sw === '6a86') throw new Error('9esim: wrong password');
    if (sw !== '9000') throw new Error('9esim: handshake ' + sw);
  }
  async transmit(apdu) {
    const body = concat(new Uint8Array([this.counter++ & 0xff]), apdu);
    const s = sum16(body);
    await this._write(concat(body, new Uint8Array([s >> 8, s & 0xff])));
    const [, payload] = await this._wait();
    const raw = payload.slice(0, -2);
    const check = (payload[payload.length - 2] << 8) | payload[payload.length - 1];
    if (sum16(raw) !== check) throw new Error('9esim: checksum');
    return raw.slice(1);
  }
  async _apdu(apdu) {
    let rsp = await this.transmit(apdu);
    let out = new Uint8Array();
    while (rsp.length >= 2 && rsp[rsp.length - 2] === 0x61) {
      out = concat(out, rsp.slice(0, -2));
      rsp = await this.transmit(new Uint8Array([0x80, 0xc0, 0x00, 0x00, rsp[rsp.length - 1]]));
    }
    return concat(out, rsp);
  }
  async connect2() {}
  async storeData(cmd) {
    if (!this._selected) {
      const sel = await this._apdu(unhex('00A4040010' + ISDR));
      if (hex(sel.slice(-2)) !== '9000') throw new Error('9esim: SELECT ISD-R ' + hex(sel.slice(-2)));
      this._selected = true;
    }
    const block = 239;
    let pos = 0, idx = 0;
    for (;;) {
      const rest = cmd.slice(pos);
      const more = rest.length > block;
      const chunk = more ? rest.slice(0, block) : rest;
      const p1 = more ? 0x11 : 0x91;
      const rsp = await this._apdu(concat(new Uint8Array([0x80, 0xe2, p1, idx, chunk.length]), chunk));
      const sw = rsp.slice(-2);
      if (more) {
        if (hex(sw) !== '9000') throw new Error('9esim: STORE DATA ' + hex(sw));
        pos += block; idx += 1; continue;
      }
      if (hex(sw) !== '9000' && sw[0] !== 0x91) throw new Error('9esim: SW ' + hex(sw));
      return rsp.slice(0, -2);
    }
  }
  /** Change the writer's BLE name suffix and password together.
   *  APDU: 30 27 00 00 09 | 11 11 11 | <suffix 3B> | <passwordHex 3B>,
   *  with a 0x80 fallback when the card answers 6E00.  Verified on hardware. */
  async setNameAndPassword(suffix, password) {
    const s = String(suffix || '').trim().toUpperCase();
    if (!/^[0-9A-F]{6}$/.test(s)) throw new Error('name suffix must be 6 hex characters');
    const p = String(password || '').trim();
    const pwHex = /^[0-9A-Fa-f]{6}$/.test(p) ? p.toUpperCase() : crc24(p);
    const data = unhex('111111' + s + pwHex);
    let last = '9000';
    for (const cla of [0x30, 0x80]) {
      const apdu = concat(new Uint8Array([cla, 0x27, 0x00, 0x00, data.length]), data);
      const rsp = await this._apdu(apdu);
      last = hex(rsp.slice(-2));
      if (last === '9000' || last === '6100') return { suffix: s, passwordHex: pwHex };
      if (last === '6e00') continue;                       // CLA unsupported, try 0x80
      break;
    }
    throw new Error(`rekey failed (SW ${last})`);
  }

  async info() {
    return { kind: '9esim', name: this.device.name, eid: await this.eid(),
             password: Esim9Card.defaultPassword(this.device.name) };
  }
}

function crc24(value) {
  let crc = 0xb704ce;
  for (const b of enc.encode(value)) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) { crc <<= 1; if (crc & 0x1000000) crc ^= 0x1864cfb; }
  }
  return (crc & 0xffffff).toString(16).padStart(6, '0').toUpperCase();
}

// ----------------------------------------------------------------- BeeSIM -- //
export class BeeSimCard extends BaseCard {
  static get label() { return 'beeesim'; }
  static filters() { return [{ namePrefix: 'BeeSIM' }]; }

  constructor(opts) { super(opts); this.channel = 1; this.buf = new Uint8Array(); this.resolve = null; }
  async connect(device) {
    this.device = device ?? this.device;
    this.server = await this.device.gatt.connect();
    const svc = await this.server.getPrimaryService(AE30);
    const chars = await svc.getCharacteristics();
    for (const ch of chars) {
      const p = ch.properties;
      if (p.notify || p.indicate) this.notify = ch;
      else if (p.write || p.writeWithoutResponse) this.write = ch;
    }
    await this.notify.startNotifications();
    this.notify.addEventListener('characteristicvaluechanged', (e) => this._onNotify(e.target.value));
    await this._initCard();
  }
  _onNotify(dv) {
    const data = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
    if (!data.length) return;
    const [total, index] = data;
    if (index === 1) this.buf = new Uint8Array();
    this.buf = concat(this.buf, data.slice(2));
    if (index >= total) { const r = this.resolve; this.resolve = null; if (r) r(this.buf); }
  }
  async _send(apdu) {
    const groups = [];
    for (let i = 0; i < apdu.length; i += 18) groups.push(apdu.slice(i, i + 18));
    if (!groups.length) groups.push(new Uint8Array());
    const p = new Promise((res) => { this.resolve = res; });
    for (let i = 0; i < groups.length; i++) {
      await this.write.writeValueWithoutResponse(concat(new Uint8Array([groups.length, i + 1]), groups[i]));
    }
    return p;
  }
  async _command(apdu) {
    let rsp = await this._send(apdu);
    if (rsp.length >= 2 && rsp[rsp.length - 2] === 0x68 && rsp[rsp.length - 1] === 0x81) {
      await this._initCard();
      rsp = await this._send(apdu);
    }
    return rsp;
  }
  async _getResponse(le, cla) {
    let out = new Uint8Array();
    for (;;) {
      const rsp = await this._command(new Uint8Array([cla, 0xc0, 0x00, 0x00, le & 0xff]));
      const body = rsp.slice(0, -2), sw1 = rsp[rsp.length - 2], sw2 = rsp[rsp.length - 1];
      out = concat(out, body);
      if (sw1 === 0x61) { le = sw2; continue; }
      return concat(out, new Uint8Array([sw1, sw2]));      // keep the SW
    }
  }
  async _initCard() {
    // Verified on hardware: no MANAGE CHANNEL (00 70 00 01 00 -> 6A86).
    // The applet is selected with CLA = channel and a pending 61xx is read with
    // the same CLA, while ES10 on that applet uses CLA 0x80|channel.
    const ch = this.channel;
    try { await this._command(unhex('80AA00000AA9088100820101830107')); } catch { /* optional */ }
    const aid = unhex(ISDR);
    let rsp = await this._command(concat(new Uint8Array([ch, 0xa4, 0x04, 0x00, aid.length]), aid));
    if (rsp[0] === 0x61) rsp = await this._getResponse(rsp[1], ch);
    if (hex(rsp.slice(-2)) !== '9000') throw new Error('beeesim: SELECT ISD-R ' + hex(rsp.slice(-2)));
  }
  async storeData(cmd) {
    const cla = 0x80 | (this.channel & 0x0f);
    const block = 239;
    let pos = 0, idx = 0;
    for (;;) {
      const rest = cmd.slice(pos);
      const more = rest.length > block;
      const chunk = more ? rest.slice(0, block) : rest;
      const p1 = more ? 0x11 : 0x91;
      let rsp = await this._command(concat(new Uint8Array([cla, 0xe2, p1, idx, chunk.length]), chunk));
      if (rsp[0] === 0x61) rsp = await this._getResponse(rsp[1], cla);
      const sw = rsp.slice(-2);
      if (more) {
        if (hex(sw) !== '9000') throw new Error('beeesim: STORE DATA ' + hex(sw));
        pos += block; idx += 1; continue;
      }
      if (hex(sw) !== '9000' && sw[0] !== 0x91) throw new Error('beeesim: SW ' + hex(sw));
      return rsp.slice(0, -2);
    }
  }
  async info() { return { kind: 'beeesim', name: this.device.name, eid: await this.eid() }; }
}

export const CARDS = { linklan: LinklanCard, '9esim': Esim9Card, beeesim: BeeSimCard };

/** Map a BLE name to a card family (same rules as `python -m blpa --card auto`). */
export function detectKind(name = '') {
  const n = name.toLowerCase();
  if (n.startsWith('beesim')) return 'beeesim';
  if (n.startsWith('9esim') || n.startsWith('esim_writer')) return '9esim';
  if (n.includes('ble-esim')) return 'linklan';
  return null;
}

/** Every GATT service the page may need, for requestDevice({optionalServices}). */
export const OPTIONAL_SERVICES = [NUS, AE30];
