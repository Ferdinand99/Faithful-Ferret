import { ops as basic } from './basic.mjs';
import { ops as items } from './items.mjs';
import { ops as checkpoint } from './checkpoint.mjs';
import { ops as rekey } from './rekey.mjs';
import { ops as text } from './text.mjs';
import { ops as exportOps } from './export.mjs';
import { ops as misc } from './misc.mjs';
import { ops as account } from './account.mjs';
import { ops as origin } from './origin.mjs';
import { ops as passkey } from './passkey.mjs';

export const registry = { ...basic, ...items, ...checkpoint, ...rekey, ...text, ...exportOps, ...misc, ...account, ...origin, ...passkey };

// Ops xcheck does not implement, with the reason shown in the report.
export const NOT_COVERED = {
  'opaque.register': 'OPAQUE (RFC 9807 with ristretto255 and the OPRF) is not implemented in xcheck: the design names the RFC but gives no byte-level construction, so a reference needs the RFC text and its own validation; the RFC vectors are run by the Rust suite',
  'opaque.login': 'same as opaque.register',
};
