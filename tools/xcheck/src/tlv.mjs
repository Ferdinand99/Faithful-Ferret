// Fase 1 section 3.1: tlv(tag, value) = tag (1 byte) || len (u16be) || value.
import { concat, u16be, ascii, XError, fail, u8, u64be } from './util.mjs';

export const T = {
  label: 0x01,
  version: 0x02,
  suite: 0x03,
  kind: 0x04,
  account_id: 0x10,
  vault_id: 0x11,
  item_id: 0x12,
  method_id: 0x13,
  method_type: 0x14,
  vk_epoch: 0x20,
  kek_generation: 0x21,
  rev: 0x22,
  seq: 0x23,
  kdf: 0x30,
  credential_id: 0x31,
  prf_salt: 0x32,
  nonce: 0x33,
  hash: 0x35,
  op: 0x36,
  device_salt: 0x37,
  salt_a: 0x38,
  header: 0x39,
};

export function tlv(tag, value) {
  if (value.length > 0xffff) fail('too_large', 'TLV value over 65535 bytes');
  return concat(Uint8Array.of(tag), u16be(value.length), value);
}

export function label(text) {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7f) fail('malformed_tlv', 'label is not ASCII');
  }
  return tlv(T.label, ascii(text));
}

export const fU8 = (tag, n) => tlv(tag, u8(n));
export const fU64 = (tag, n) => tlv(tag, u64be(n));
export const fBytes = (tag, b) => tlv(tag, b);

// Concatenation of already-encoded fields, nothing between them.
export const tlvs = (...fields) => concat(...fields);

export { XError };
