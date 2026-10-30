// origin.*
import { unhex, utf8 } from '../util.mjs';
import { canonicalOrigin, validateRpId } from '../origin.mjs';

export const ops = {};

const text = (hexText) => new TextDecoder('utf-8').decode(unhex(hexText));

ops['origin.canonical'] = ({ input }) => {
  const r = canonicalOrigin(text(input.raw_utf8));
  return { expect: { origin: r.origin, host: r.host } };
};

ops['origin.rp_id'] = ({ input }) => {
  const o = canonicalOrigin(text(input.origin_utf8));
  return { expect: { rp_id: validateRpId(text(input.rp_id_utf8), o.host) } };
};

export { utf8 };
