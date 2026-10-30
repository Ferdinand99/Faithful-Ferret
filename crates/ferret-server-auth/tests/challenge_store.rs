//! The memory challenge store passes the checks every challenge store must.

use ferret_server_auth::InMemoryChallengeStore;
use ferret_server_auth::testing::challenge_conformance;

#[test]
fn challenge_store_conformance() {
    challenge_conformance(InMemoryChallengeStore::with_capacity);
}
