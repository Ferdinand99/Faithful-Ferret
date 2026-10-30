// passkey.*
import { unhex, hex, segmentsToBytes } from '../util.mjs';
import { create, get, prfSalt, prfOutput } from '../passkey.mjs';

export const ops = {};

ops['passkey.create'] = ({ input, rng }) => create(input, rng);
ops['passkey.get'] = ({ input, expected }) => get(input, expected);

ops['passkey.prf'] = ({ input }) => {
  const data = segmentsToBytes(input.input);
  return { expect: { salt: hex(prfSalt(data)), output: hex(prfOutput(unhex(input.seed), data)) } };
};
