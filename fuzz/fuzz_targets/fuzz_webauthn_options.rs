//! `CreateRequest::validate` and `GetRequest::validate` on arbitrary request
//! structures, and the two ceremonies on the requests that pass: never a
//! panic, and a request that validates stays inside the limits (plan section
//! 9.2).
#![no_main]

use ferret_core::passkey::{PrfCreate, PrfEval, PrfRequest};
use ferret_core::testing::TestRng;
use ferret_core::{
    CallerContext, CreateRequest, GetRequest, UserVerification, UvOutcome, canonical_origin,
    passkey_create, passkey_get,
};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Eval {
    first: Vec<u8>,
    second: Option<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    challenge: Vec<u8>,
    rp_id: Option<String>,
    rp_name: String,
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    algorithms: Vec<i64>,
    exclude: Vec<Vec<u8>>,
    allow: Vec<Vec<u8>>,
    uv_kind: u8,
    present: bool,
    verified: bool,
    create_prf: Option<Option<Eval>>,
    get_eval: Option<Eval>,
    by_credential: Vec<(Vec<u8>, Eval)>,
    use_get_prf: bool,
}

fn eval(e: Eval) -> PrfEval {
    PrfEval {
        first: e.first,
        second: e.second,
    }
}

fuzz_target!(|i: Input| {
    let uv_kind = match i.uv_kind % 3 {
        0 => UserVerification::Required,
        1 => UserVerification::Preferred,
        _ => UserVerification::Discouraged,
    };
    let create = CreateRequest {
        challenge: i.challenge.clone(),
        rp_id: i.rp_id.clone(),
        rp_name: i.rp_name,
        user_id: i.user_id,
        user_name: i.user_name,
        user_display_name: i.user_display_name,
        algorithms: i.algorithms,
        exclude: i.exclude,
        user_verification: uv_kind,
        prf: i.create_prf.map(|p| PrfCreate { eval: p.map(eval) }),
    };
    let get = GetRequest {
        challenge: i.challenge,
        rp_id: i.rp_id,
        allow: i.allow,
        user_verification: uv_kind,
        prf: i.use_get_prf.then(|| PrfRequest {
            eval: i.get_eval.map(eval),
            eval_by_credential: i
                .by_credential
                .into_iter()
                .map(|(id, e)| (id, eval(e)))
                .collect(),
        }),
    };
    let ctx = CallerContext {
        origin: canonical_origin("https://login.example.com").expect("a valid origin"),
        top_origin_is_same: true,
    };
    let uv = UvOutcome {
        user_present: i.present,
        user_verified: i.verified,
    };

    if create.validate().is_ok() {
        assert!(create.challenge.len() <= 1024 && create.exclude.len() <= 200);
        assert!((1..=64).contains(&create.user_id.len()));
        let mut rng = TestRng::new(b"fuzz");
        if let Ok(made) = passkey_create(&mut rng, &create, &ctx, uv, &[], 0) {
            let _ = passkey_get(&made.record, &get, &ctx, uv);
        }
    }
    if get.validate().is_ok() {
        assert!(get.challenge.len() <= 1024 && get.allow.len() <= 200);
    }
});
