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
import { ops as methods } from './methods.mjs';
import { ops as server } from './server.mjs';

export const registry = { ...basic, ...items, ...checkpoint, ...rekey, ...text, ...exportOps, ...misc, ...account, ...origin, ...passkey, ...methods, ...server };

// Ops xcheck does not implement, with the reason shown in the report.
export const NOT_COVERED = {
  'opaque.register': 'OPAQUE (RFC 9807 with ristretto255 and the OPRF) is not implemented in xcheck: the design names the RFC but gives no byte-level construction, so a reference needs the RFC text and its own validation; the RFC vectors are run by the Rust suite',
  'opaque.login': 'same as opaque.register',
  'server.register_response': 'needs the OPRF of RFC 9807 (ristretto255): not implemented in xcheck, see opaque.register; recorded from the server and tied to the RFC by crates/ferret-server-auth/tests/rfc9807_server.rs',
  'server.login_start': 'needs the 3DH key exchange and the masking of RFC 9807: not implemented in xcheck, see opaque.register; recorded from the server (regression pin). The made-up id, answer and record that go into it are covered by server.fake_*',
  'server.login_finish': 'needs the 3DH key exchange of RFC 9807: not implemented in xcheck, see opaque.register; recorded from the server (regression pin). The sealed state it opens is covered by server.state_open',
  'server.replace_authorize': 'needs the ristretto255 check of the uploaded OPAQUE record; the Ed25519 proof inside it is covered by proof.verify. Recorded from the server (regression pin)',
};
