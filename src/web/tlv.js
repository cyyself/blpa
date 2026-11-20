// BER-TLV + SGP.22 helpers shared by the three transports (port of blpa/tlv.py)
export function encode(tag, ...children) {
  const t = typeof tag === 'number' ? tagBytes(tag) : tag;
  const body = concat(...children.map((c) => (c instanceof Uint8Array ? c : new Uint8Array(c))));
  return concat(t, len(body.length), body);
}
export const tagBytes = (tag) => (tag <= 0xff ? [tag] : tag <= 0xffff ? [tag >> 8, tag & 0xff] : [(tag >> 16) & 0xff, (tag >> 8) & 0xff, tag & 0xff]);
export const len = (n) => (n < 0x80 ? [n] : n <= 0xff ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export function decode(data) {
  const out = [];
  let i = 0;
  while (i < data.length) {
    let tag = data[i++];
    if ((tag & 0x1f) === 0x1f) {
      let b;
      do { b = data[i++]; tag = (tag << 8) | b; } while (b & 0x80);
    }
    let ln = data[i++];
    if (ln === 0x81) ln = data[i++];
    else if (ln === 0x82) { ln = (data[i] << 8) | data[i + 1]; i += 2; }
    else if (ln === 0x83) { ln = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]; i += 3; }
    out.push([tag, data.slice(i, i + ln)]);
    i += ln;
  }
  return out;
}

export const dict = (data) => Object.fromEntries(decode(data));
export function find(data, ...tags) {
  let value = data;
  for (const tag of tags) {
    if (!value) return null;
    const m = dict(value);
    value = m[tag];
    if (value === undefined) return null;
  }
  return value;
}

export const bcd = (bytes, swap = false) => {
  let s = '';
  for (const b of bytes) {
    const n = swap ? [b & 0xf, b >> 4] : [b >> 4, b & 0xf];
    for (const x of n) if (x !== 0xf) s += x.toString(16).toUpperCase();
  }
  return s;
};

export function toBcd(text, swap = false) {
  let s = text.replace(/ /g, '').toUpperCase();
  if (s.length % 2) s += 'F';
  const raw = s.match(/../g).map((h) => parseInt(h, 16));
  return new Uint8Array(swap ? raw.map((b) => ((b & 0xf) << 4) | (b >> 4)) : raw);
}

// --- ES10 commands (identical on all three cards) ------------------------- //
export const cmdEid = () => encode(0xbf3e, encode(0x5c, new Uint8Array([0x5a])));
export const cmdProfiles = () => encode(0xbf2d, encode(0x5c, new Uint8Array([0x5a, 0x90, 0x91, 0x92, 0xb7, 0x9f, 0x70, 0x95, 0x99])));
const profileBody = (iccid, ...extra) => encode(0xa0, concat(encode(0x5a, toBcd(iccid, true)), ...extra));
export const cmdEnable = (iccid) => encode(0xbf31, profileBody(iccid, encode(0x81, new Uint8Array([0xff]))));
export const cmdDisable = (iccid) => encode(0xbf32, profileBody(iccid));
export const cmdDelete = (iccid) => encode(0xbf33, profileBody(iccid));
export const cmdNickname = (iccid, nick) => encode(0xbf29, encode(0x5a, toBcd(iccid, true)), encode(0x90, new TextEncoder().encode(nick)));
export const cmdNotifications = () => encode(0xbf28, new Uint8Array(0));

export function resultCode(rsp, tag) {
  const body = dict(rsp)[tag];
  if (!body) return 0xff;
  const code = dict(body)[0x80];
  return code && code.length ? code[0] : 0xff;
}

export function parseProfiles(rsp) {
  const body = dict(rsp)[0xbf2d];
  if (!body) return [];
  const container = dict(body)[0xa0];
  if (!container) return [];
  const out = [];
  for (const [tag, value] of decode(container)) {
    if (tag !== 0xe3) continue;
    const f = dict(value);
    const txt = (k) => (f[k] ? new TextDecoder().decode(f[k]) : '');
    out.push({
      iccid: bcd(f[0x5a] ?? new Uint8Array(), true),
      enabled: f[0x9f70] && f[0x9f70][0] === 1,
      nickname: txt(0x90), name: txt(0x91), provider: txt(0x92),
      profileClass: f[0x95] ? f[0x95][0] : 0,
    });
  }
  return out;
}
