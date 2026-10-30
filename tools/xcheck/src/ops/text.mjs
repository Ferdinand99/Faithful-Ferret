// text.*, code.*
import { unhex, hex, fail, concat, textInputToBytes, utf8 } from '../util.mjs';
import { checkText, masterPassword, encodeCode, decodeCode, MIN_EXPORT, MIN_WITH_SK } from '../text.mjs';

export const ops = {};

ops['text.nfkd'] = ({ input }) => {
  const r = checkText(textInputToBytes(input), 0);
  return { expect: { nfkd: hex(r.nfkd) } };
};

ops['text.mp'] = ({ input }) => ({ expect: { mp: hex(masterPassword(textInputToBytes(input), input.policy).nfkd) } });

ops['text.opaque_input'] = ({ input }) => {
  const mp = masterPassword(textInputToBytes(input), input.policy).nfkd;
  const sk = input.secret_key ? unhex(input.secret_key) : null;
  return { expect: { opaque_input: hex(sk ? concat(mp, Uint8Array.of(0), sk) : mp) } };
};

ops['text.export_password'] = ({ input }) => {
  const r = checkText(textInputToBytes(input), MIN_EXPORT);
  if (input.master_password) {
    const mp = masterPassword(textInputToBytes(input.master_password), 'with_secret_key').nfkd;
    if (hex(mp) === hex(r.nfkd)) fail('input_same_as_master_password');
  }
  return { expect: { export_password: hex(r.nfkd) } };
};

ops['code.rk.encode'] = ({ input }) => ({ expect: { code: encodeCode('rk', unhex(input.key)) } });
ops['code.sk.encode'] = ({ input }) => ({ expect: { code: encodeCode('sk', unhex(input.key)) } });
ops['code.rk.decode'] = ({ input }) => ({ expect: { key: hex(decodeCode('rk', input.code)) } });
ops['code.sk.decode'] = ({ input }) => ({ expect: { key: hex(decodeCode('sk', input.code)) } });

export { utf8, MIN_WITH_SK };
