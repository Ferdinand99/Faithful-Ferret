// export.*
import { unhex, hex, utf8 } from '../util.mjs';
import { checkText, MIN_EXPORT } from '../text.mjs';
import { encryptExport, decryptExport, parseHeader, plainJson, plainCsv } from '../export.mjs';
import { encode } from '../cbor.mjs';

export const ops = {};

const itemsOf = (list) => list.map((i) => ({ id: unhex(i.id), body: unhex(i.body) }));

ops['export.encrypt'] = ({ input, rng, tags }) => {
  const password = checkText(utf8(input.password), MIN_EXPORT).nfkd;
  const r = encryptExport({
    password,
    kdf: input.kdf,
    createdAt: BigInt(input.created_at),
    items: itemsOf(input.items),
    draw: (n) => rng.draw(n),
    // a case tagged native-only uses parameters below the floor: only a test-support build takes them
    unchecked: tags.includes('native-only'),
  });
  return { expect: { file: hex(r.file) }, intermediate: { header: hex(r.header), k_exp: hex(r.kExp), aad_ek: hex(r.aadEk), aad_body: hex(r.aadBody) } };
};

ops['export.decrypt'] = ({ input, tags }) => {
  const password = checkText(utf8(input.password), 0).nfkd;
  const r = decryptExport({ password, file: unhex(input.file), unchecked: tags.includes('native-only') });
  return {
    expect: {
      created_at: String(r.createdAt),
      kdf: r.kdf,
      items: r.items.map((i) => ({ id: hex(i.id), body: hex(encode(i.value)) })),
    },
  };
};

ops['export.header'] = ({ input }) => {
  const h = parseHeader(unhex(input.file));
  return { expect: { created_at: String(h.createdAt), kdf: { m_kib: Number(h.m), t: Number(h.t), p: Number(h.p) }, salt: hex(h.salt), header_len: h.headerLen } };
};

ops['export.plain.json'] = ({ input }) => ({ expect: { text: plainJson(itemsOf(input.items), input.include_passkeys) } });
ops['export.plain.csv'] = ({ input }) => ({ expect: { text: plainCsv(itemsOf(input.items)) } });
