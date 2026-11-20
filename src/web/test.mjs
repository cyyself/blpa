// node src/web/test.mjs — validates the JS against Python-generated vectors
import fs from 'node:fs';
import { hex, unhex, aesccmEncrypt, aesccmDecrypt, tripleDesEcb } from './crypto.js';
import * as tlv from './tlv.js';
import { CARDS } from './transports.js';

const v = JSON.parse(fs.readFileSync(new URL('./vectors.json', import.meta.url)));
let failures = 0;
const check = (name, ok, extra = '') => {
  console.log(`${name.padEnd(10)} ${ok ? 'OK' : 'FAIL'}  ${extra}`);
  if (!ok) failures++;
};

const ct = await aesccmEncrypt(unhex(v.aesccm.key), unhex(v.aesccm.nonce), unhex(v.aesccm.aad), unhex(v.aesccm.pt));
check('aesccm', hex(ct) === v.aesccm.ct);
const pt = await aesccmDecrypt(unhex(v.aesccm.key), unhex(v.aesccm.nonce), unhex(v.aesccm.aad), ct);
check('aesccm D', hex(pt) === v.aesccm.pt);
const t = tripleDesEcb(unhex(v.tdes.key), unhex(v.tdes.pt));
check('3des', hex(t) === v.tdes.ct);
check('3des D', hex(tripleDesEcb(unhex(v.tdes.key), unhex(v.tdes.ct), true)) === v.tdes.pt);

  const e3 = tlv.encode(0xE3,
    tlv.encode(0x5A, tlv.toBcd('8900000000000000001', true)),
    tlv.encode(0x9F70, new Uint8Array([0])),
    tlv.encode(0x91, new TextEncoder().encode('Speedtest Travel')),
    tlv.encode(0x92, new TextEncoder().encode('BetterRoaming')),
    tlv.encode(0x95, new Uint8Array([2])));
  const captured = hex(tlv.encode(0xBF2D, tlv.encode(0xA0, e3)));
  const profiles = tlv.parseProfiles(unhex(captured));
check('tlv', profiles.length === 1 && profiles[0].iccid === '8900000000000000001' && profiles[0].name === 'Speedtest Travel');
check('cmdEnable', hex(tlv.cmdEnable('8900000000000000002')) === 'bf3111a00f5a0a980000000000000000f28101ff');
check('9esim key', hex(CARDS['9esim'].authKey('DEMO123456')) === '56654321566543215665432100000000');
check('resultCode', tlv.resultCode(unhex('bf3103800100'), 0xbf31) === 0);

// --- the AUTH frame must match the bytes the real client sends ------------- //
{
  const { LinklanCard } = await import('./transports.js');
  const card = new LinklanCard({ password: '000000' });
  await card.setCredentials({ password: '000000' });
  let sent = null;
  // answer the AUTH with the UPDATE the card really sends, and capture the frame
  card._send = async (frame) => {
    sent = frame;
    return unhex('1a4608011a420a0c31ea7bbc04d9dfdb9c755f7912100a393c8d16cbabc48bc05bac8d5dd5211a20abee6385870c2447b28aa49a5118ad04e20877f33d07c8d55fcd8be426bfdf'.slice(0, 140));
  };
  const challenge = unhex('12120a1000112233445566778899aabbccddeeff');   // SecurityProtocol{2:{1:random}}
  try { await card._authenticate(challenge); } catch { /* the fake UPDATE is truncated */ }
  // real client: 0803 123a 0800 1a36 1234 0a10 <16B random> 1220 <32B proof>
  const ok = sent && hex(sent).startsWith('0803123a08001a3612340a10') && sent.length === 62;
  check('authframe', ok, sent ? hex(sent).slice(0, 40) + '…' : 'no frame');
}

// --- 9eSIM rekey APDU (verified on hardware) ------------------------------- //
{
  const { Esim9Card } = await import('./transports.js');
  const c = new Esim9Card({});
  const sent = [];
  c._apdu = async (a) => { sent.push(hex(a)); return unhex('9000'); };
  const out = await c.setNameAndPassword('250401', '654321');
  check('rekey', sent[0] === '3027000009111111250401654321' && out.passwordHex === '654321');
}

// --- envelope classification against real card bytes ---------------------- //
{
  const { LinklanCard } = await import('./transports.js');
  const card = new LinklanCard({});
  const cases = [
    // challenge from DeviceRsp.security (field 5) - captured from the hardware
    ['08012a1412120a10de040af3c8389570b04eea720c3e6891', 'protocol'],
    // AUTH answered with a bare { 3: SecurityProtocol{UPDATE} } - captured
    ['1a4608011a420a0c31ea7bbc04d9dfdb9c755f7912100a393c8d16cbabc48bc05bac8d5dd5211a20abee6385870c2447b28aa49d8a5118ad04e20877f33d07c8d55fcd8be426bfdf', 'protocol'],
    // encrypted reply: bare SecurityData{ id = 1, enc = ... }
    ['0801120a00112233445566778899', 'enc'],
    // ... and the counter == 3 case, which looks like a nested {cmd=3, request}
    ['0803120a00112233445566778899', 'enc'],
    // plaintext device info (DeviceInfo in field 3, vendor string in field 1)
    ['08031a0a0a084c696e6b73666e', 'plain'],
    // protocol error
    ['2805', 'error'],
  ];
  let ok = true;
  for (const [rsp, want] of cases) {
    const [kind] = await card._classify(unhex(rsp));
    if (kind !== want) { ok = false; console.log(`classify ${rsp.slice(0, 16)}… -> ${kind}, want ${want}`); }
  }
  check('classify', ok);
}

process.exit(failures ? 1 : 0);
