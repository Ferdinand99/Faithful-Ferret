// totp.*, sheet.qr.*
import { unhex, hex } from '../util.mjs';
import { parseOtpauth, totpCode } from '../totp.mjs';
import { buildPayload, parsePayload } from '../sheet.mjs';

export const ops = {};

ops['totp.parse'] = ({ input }) => {
  const p = parseOtpauth(input.uri);
  return { expect: { secret: hex(p.secret), algorithm: p.algorithm, digits: p.digits, period: p.period, issuer: p.issuer, label: p.label } };
};

ops['totp.code'] = ({ input }) => {
  const r = totpCode(parseOtpauth(input.uri), input.unix_seconds);
  return { expect: { code: r.code, seconds_left: r.secondsLeft } };
};

ops['sheet.qr.build'] = ({ input }) => ({
  expect: {
    payload: buildPayload({ url: input.server_url, accountId: unhex(input.account_id), profile: input.ksf_profile, skBit: input.sk_bit, serverKey: unhex(input.server_public_key) }),
  },
});

ops['sheet.qr.parse'] = ({ input }) => {
  const r = parsePayload(input.payload);
  return { expect: { server_url: r.url, account_id: hex(r.accountId), ksf_profile: r.profile, sk_bit: r.skBit, server_public_key: hex(r.serverKey) } };
};
