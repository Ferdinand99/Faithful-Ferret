//! `POST /api/vault/unlock-methods` and `DELETE /api/vault/unlock-methods/{id}`:
//! adding and removing a passkey (PRF) unlock method.
//!
//! The client is the one of `ferret-core`: it wraps the vault key for the
//! passkey, makes the next manifest and the exact body, and signs the body
//! with `sk_a`. The routes are in a build with the cargo feature
//! `quick-unlock` only. Spec: Fase 1 § 4.3, § 4.6 and § 7.2.

mod support;

#[cfg(feature = "quick-unlock")]
mod with_routes {
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use axum::http::{Method, StatusCode};
    use ferret_core::passkey::AAGUID;
    use ferret_core::{
        AuthOp, CurrentManifest, Kek, Method as WrapMethod, MethodChange, PasskeyMeta, PrfOutput,
        auth_sign, manifest_add_method, manifest_remove_method,
    };
    use ferret_server::auth::session::{Origin, lookup, set_parent};
    use ferret_server::http::proxy_guard::ProxyList;
    use ferret_server::ids::{AccountId, MethodId, SidHash};
    use ferret_server::wire::{b64url, hex16};
    use ferret_server_auth::{Clock as _, SessionScope};
    use serde_json::{Value, json};
    use tracing_subscriber::fmt::MakeWriter;

    use crate::support::accounts::{
        Client, Snapshot, client_account, client_session, id16, send_signed, snapshot,
    };
    use crate::support::device::{DeviceClient, device_app};
    use crate::support::session::{issue, nonce_for};
    use crate::support::{Jar, PEER, Req, Res, TestApp, Which};

    const PATH: &str = "/api/vault/unlock-methods";
    const SECOND: Duration = Duration::from_secs(1);

    /// A change to the JSON of a body.
    type Edit = Box<dyn Fn(&mut Value)>;

    // -------------------------------------------------------------- helpers

    async fn app() -> TestApp {
        let proxies =
            ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("proxies");
        TestApp::builder().proxies(proxies).build().await
    }

    /// An app with client account `n` and a fresh full session of it.
    async fn setup(n: u8) -> (TestApp, Client, Jar, SidHash) {
        let app = app().await;
        let client = client_account(&app, n).await;
        let issued = client_session(&app, &client, SessionScope::Full, 1).await;
        (app, client, issued.jar, issued.sid)
    }

    fn error_of(res: &Res) -> String {
        res.json()["error"].as_str().unwrap_or("").to_string()
    }

    /// A passkey as a registration gives it.
    #[derive(Clone)]
    struct Passkey {
        method_id: [u8; 16],
        credential_id: Vec<u8>,
        prf_salt: [u8; 32],
        aaguid: [u8; 16],
        name: &'static str,
        be: bool,
        bs: bool,
    }

    impl Passkey {
        fn new(n: u8) -> Self {
            Passkey {
                method_id: id16(0xe0, n),
                credential_id: vec![n; 20 + usize::from(n)],
                prf_salt: [n | 0x40; 32],
                aaguid: [0x9d; 16],
                name: "Work laptop",
                be: false,
                bs: false,
            }
        }
    }

    /// The change that adds `pk`, as the core makes it from the manifest the
    /// server holds.
    fn add_change(client: &mut Client, pk: &Passkey) -> MethodChange {
        let output = PrfOutput::from_slice(&[pk.prf_salt[0] ^ 0x5a; 32]).expect("a PRF output");
        let kek = Kek::from_prf(&pk.credential_id, &output).expect("a key");
        let wrap = client
            .vault
            .wrap_for_method(
                &mut client.rng,
                &kek,
                MethodId::from_bytes(pk.method_id),
                1,
                WrapMethod::Prf {
                    credential_id: pk.credential_id.clone(),
                    prf_salt: pk.prf_salt,
                },
            )
            .expect("a wrap");
        manifest_add_method(
            &mut client.rng,
            &client.vault,
            &CurrentManifest {
                rev: client.manifest.rev,
                envelope: &client.manifest.envelope,
                tag: &client.manifest.tag,
            },
            wrap,
            &PasskeyMeta {
                aaguid: pk.aaguid,
                name: pk.name,
                be: pk.be,
                bs: pk.bs,
            },
        )
        .expect("the core adds the passkey")
    }

    /// The change that removes the method `id`.
    fn remove_change(client: &mut Client, id: [u8; 16]) -> MethodChange {
        manifest_remove_method(
            &mut client.rng,
            &client.vault,
            &CurrentManifest {
                rev: client.manifest.rev,
                envelope: &client.manifest.envelope,
                tag: &client.manifest.tag,
            },
            &MethodId::from_bytes(id),
        )
        .expect("the core removes the passkey")
    }

    fn remove_path(id: &[u8; 16]) -> String {
        format!("{PATH}/{}", hex16::encode(id))
    }

    /// `body` for `op` as the client signs and sends it: over a fresh nonce of
    /// the session of `jar`.
    async fn send_body(
        app: &TestApp,
        jar: &Jar,
        client: &Client,
        op: AuthOp,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Res {
        let nonce = nonce_for(app, jar).await;
        let proof = auth_sign(&client.vault, op, &nonce, &body).expect("a proof");
        send_signed(app, jar, method, path, &nonce, &proof, body).await
    }

    /// `POST` of `change` exactly as the core made it.
    async fn post(app: &TestApp, jar: &Jar, client: &Client, change: &MethodChange) -> Res {
        send_body(
            app,
            jar,
            client,
            change.op,
            Method::POST,
            PATH,
            change.body.clone(),
        )
        .await
    }

    /// `POST` of the body of `change` with `edit` applied to its JSON (the
    /// bytes are the edited ones, and the proof is over them).
    async fn post_edited(
        app: &TestApp,
        jar: &Jar,
        client: &Client,
        change: &MethodChange,
        edit: impl FnOnce(&mut Value),
    ) -> Res {
        send_body(
            app,
            jar,
            client,
            change.op,
            Method::POST,
            PATH,
            edited(change, edit),
        )
        .await
    }

    fn edited(change: &MethodChange, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut json: Value = serde_json::from_slice(&change.body).expect("a JSON body");
        edit(&mut json);
        serde_json::to_vec(&json).expect("a body")
    }

    /// `DELETE` of `change` at the URL for `id`.
    async fn delete(
        app: &TestApp,
        jar: &Jar,
        client: &Client,
        change: &MethodChange,
        id: &[u8; 16],
    ) -> Res {
        send_body(
            app,
            jar,
            client,
            change.op,
            Method::DELETE,
            &remove_path(id),
            change.body.clone(),
        )
        .await
    }

    /// The state of the client after the server took `change`.
    fn took(app: &TestApp, client: &mut Client, change: &MethodChange) {
        app.backup_status().take_request();
        client.manifest = change.sealed.clone();
    }

    /// A refused request left the account as it was and asked for no backup.
    async fn nothing_changed(app: &TestApp, client: &Client, before: &Snapshot) {
        assert_eq!(&snapshot(app, client).await, before);
        assert!(
            !app.backup_status().has_request(),
            "no backup was asked for"
        );
    }

    /// The passkey rows of an account:
    /// `(method_id, generation, wrap, credential_id, prf_salt, aaguid)`.
    type PrfRow = ([u8; 16], i64, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

    async fn prf_rows(app: &TestApp, account: AccountId) -> Vec<PrfRow> {
        app.state
            .vault_db
            .with_conn(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT method_id, kek_generation, wrap, credential_id, prf_salt, aaguid
                     FROM ferret_unlock_methods WHERE account_id = ?1 AND method_type = 3
                     ORDER BY created_at, method_id",
                )?;
                let rows = stmt
                    .query_map([account.as_bytes().as_slice()], |r| {
                        let id: Vec<u8> = r.get(0)?;
                        Ok((
                            <[u8; 16]>::try_from(id).expect("16 bytes"),
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .expect("the passkey rows")
    }

    async fn vault_get(app: &TestApp, jar: &Jar, path: &str) -> Res {
        let mut req = Req::get(path)
            .header("ferret-protocol", "1")
            .header("sec-fetch-site", "same-origin");
        if let Some(cookie) = jar.header() {
            req = req.header("cookie", &cookie);
        }
        app.call_raw(Which::Vault, req.build()).await
    }

    async fn ended(app: &TestApp, sid: SidHash) -> bool {
        app.state
            .vault_db
            .with_conn(move |conn| Ok(lookup(conn, &sid)?))
            .await
            .expect("a row")
            .expect("the session")
            .revoked_at
            .is_some()
    }

    // ---------------------------------------------------------------- tests

    #[tokio::test]
    async fn adding_a_prf_method_needs_fresh_reauth_and_a_signature_over_the_exact_body() {
        let app = app().await;
        let mut client = client_account(&app, 1).await;
        let before = snapshot(&app, &client).await;
        let pk = Passkey::new(1);
        let change = add_change(&mut client, &pk);

        // A full session that never proved the password again, and one that
        // did, 301 seconds ago.
        let stale = issue(
            &app,
            client.ids.user_id,
            Origin::Vault,
            SessionScope::Full,
            1,
        )
        .await;
        let res = post(&app, &stale.jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
        assert_eq!(error_of(&res), "reauth_required");
        nothing_changed(&app, &client, &before).await;
        let aged = client_session(&app, &client, SessionScope::Full, 2).await;
        app.clock.advance(301);
        let res = post(&app, &aged.jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
        assert_eq!(error_of(&res), "reauth_required");
        nothing_changed(&app, &client, &before).await;

        // A fresh session with a proof that is not for this operation, or
        // not by this account, or not over this body, is refused.
        let fresh = client_session(&app, &client, SessionScope::Full, 3).await;
        for (what, op) in [
            ("the remove proof", AuthOp::UnlockMethodRemove),
            ("the password proof", AuthOp::UnlockMethodPasswordPut),
            ("the recovery proof", AuthOp::UnlockMethodRecoveryPut),
        ] {
            let res = send_body(
                &app,
                &fresh.jar,
                &client,
                op,
                Method::POST,
                PATH,
                change.body.clone(),
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::UNAUTHORIZED,
                "{what}: {}",
                res.text()
            );
            assert_eq!(error_of(&res), "denied", "{what}");
            nothing_changed(&app, &client, &before).await;
        }
        let stranger = client_account(&app, 2).await;
        let nonce = nonce_for(&app, &fresh.jar).await;
        let proof = auth_sign(&stranger.vault, change.op, &nonce, &change.body).expect("a proof");
        let res = send_signed(
            &app,
            &fresh.jar,
            Method::POST,
            PATH,
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        let before = snapshot(&app, &client).await;

        // The signature of the core over the body it made goes through.
        let nonce = nonce_for(&app, &fresh.jar).await;
        let proof = change.sign(&client.vault, &nonce).expect("a proof");
        let res = send_signed(
            &app,
            &fresh.jar,
            Method::POST,
            PATH,
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert_eq!(res.json(), json!({"seq": 2}));
        assert_eq!(res.header("cache-control"), "no-store");

        // The passkey row is the one that was sent, at generation 1, and the
        // manifest is the next revision at the vault's next `seq`.
        let rows = prf_rows(&app, client.ids.account_id).await;
        let wrap = change.wrap.as_ref().expect("a wrap");
        assert_eq!(
            rows,
            [(
                pk.method_id,
                1,
                wrap.wrap.clone(),
                pk.credential_id.clone(),
                pk.prf_salt.to_vec(),
                Some(pk.aaguid.to_vec())
            )]
        );
        let after = snapshot(&app, &client).await;
        assert_eq!(
            (after.manifest_rev, after.manifest_seq, after.vault_seq),
            (2, 2, 2)
        );
        assert_eq!(after.manifest_envelope, change.sealed.envelope);
        assert_eq!(after.manifest_tag, change.sealed.tag.to_vec());
        assert_eq!(after.wraps.len(), before.wraps.len() + 1);
        // The password and recovery rows, the record and the keys are untouched.
        assert_eq!(&after.wraps[..2], &before.wraps[..2]);
        assert_eq!(
            (&after.record, &after.pk_a, &after.pk_r, after.vk_epoch),
            (&before.record, &before.pk_a, &before.pk_r, before.vk_epoch)
        );

        // The list shows it with its AAGUID, and the other two methods
        // without one.
        let res = vault_get(&app, &fresh.jar, PATH).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let listed = res.json()["methods"].clone();
        let passkey = listed
            .as_array()
            .expect("a list")
            .iter()
            .find(|m| m["method_type"] == json!(3))
            .expect("the passkey");
        assert_eq!(passkey["method_id"], json!(hex16::encode(&pk.method_id)));
        assert_eq!(passkey["aaguid"], json!(hex16::encode(&pk.aaguid)));
        assert_eq!(
            passkey["credential_id"],
            json!(b64url::encode(&pk.credential_id))
        );
        assert_eq!(passkey["prf_salt"], json!(b64url::encode(&pk.prf_salt)));
        assert_eq!(passkey["kek_generation"], json!(1));
        assert_eq!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m.get("aaguid").is_some())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_spent_nonce_or_a_changed_byte_is_denied() {
        let (app, mut client, jar, _) = setup(3).await;
        let before = snapshot(&app, &client).await;
        let change = add_change(&mut client, &Passkey::new(1));

        // One more byte after the proof was made.
        let nonce = nonce_for(&app, &jar).await;
        let proof = change.sign(&client.vault, &nonce).expect("a proof");
        let mut other = change.body.clone();
        other.push(b' ');
        let res = send_signed(&app, &jar, Method::POST, PATH, &nonce, &proof, other).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        assert_eq!(error_of(&res), "denied");
        nothing_changed(&app, &client, &before).await;

        // A byte of the credential changed, with the proof of the original.
        let nonce = nonce_for(&app, &jar).await;
        let proof = change.sign(&client.vault, &nonce).expect("a proof");
        let text = String::from_utf8(change.body.clone()).expect("text");
        let credential = text.find("\"credential_id\":\"").expect("a credential") + 17;
        let mut bytes = text.into_bytes();
        bytes[credential] = if bytes[credential] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let res = send_signed(&app, &jar, Method::POST, PATH, &nonce, &proof, bytes).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        nothing_changed(&app, &client, &before).await;

        // The nonce is gone with the refusal: the right proof over it is
        // refused now.
        let res = send_signed(
            &app,
            &jar,
            Method::POST,
            PATH,
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        nothing_changed(&app, &client, &before).await;

        // A nonce that was used for a request that went through is spent too.
        let nonce = nonce_for(&app, &jar).await;
        let proof = change.sign(&client.vault, &nonce).expect("a proof");
        let res = send_signed(
            &app,
            &jar,
            Method::POST,
            PATH,
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let again = send_signed(
            &app,
            &jar,
            Method::POST,
            PATH,
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{}", again.text());
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 1);

        // A nonce that was never issued.
        let res = send_signed(&app, &jar, Method::POST, PATH, &[1; 32], &[2; 64], vec![]).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    }

    #[tokio::test]
    async fn a_second_method_with_the_same_credential_is_refused() {
        let (app, mut client, jar, _) = setup(4).await;
        let first = Passkey::new(1);
        let change = add_change(&mut client, &first);
        assert_eq!(
            post(&app, &jar, &client, &change).await.status,
            StatusCode::OK
        );
        took(&app, &mut client, &change);
        let before = snapshot(&app, &client).await;

        // Another method id, the same credential: the core would refuse it
        // (the manifest lists the credential), so the body is edited.
        let mut second = Passkey::new(2);
        second.credential_id = vec![9; 33];
        let change = add_change(&mut client, &second);
        let credential = hex(&first.credential_id);
        let res = post_edited(&app, &jar, &client, &change, |body| {
            body["credential_id"] = json!(credential);
        })
        .await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
        assert_eq!(error_of(&res), "conflict");
        nothing_changed(&app, &client, &before).await;

        // The same method id with another credential, and the id of the
        // password wrap: refused alike.
        for id in [first.method_id, id16(0xc1, 4)] {
            let res = post_edited(&app, &jar, &client, &change, |body| {
                body["method_id"] = json!(hex16::encode(&id));
            })
            .await;
            assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
            assert_eq!(error_of(&res), "conflict");
            nothing_changed(&app, &client, &before).await;
        }

        // The passkey as made goes through.
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 2);
    }

    #[tokio::test]
    async fn a_zero_aaguid_is_stored_and_ferrets_own_is_refused() {
        let (app, mut client, jar, _) = setup(5).await;

        // All zero: stored as sent, and listed as 32 zeros.
        let mut zero = Passkey::new(1);
        zero.aaguid = [0; 16];
        let change = add_change(&mut client, &zero);
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        took(&app, &mut client, &change);
        let rows = prf_rows(&app, client.ids.account_id).await;
        assert_eq!(rows[0].5, Some(vec![0; 16]));
        let listed = vault_get(&app, &jar, PATH).await.json();
        let listed = listed["methods"].as_array().expect("a list").clone();
        assert_eq!(
            listed
                .iter()
                .find(|m| m["method_type"] == json!(3))
                .expect("a passkey")["aaguid"],
            json!("00".repeat(16))
        );

        // Left out or `null`: stored as none, and not listed.
        let edits: Vec<(u8, Edit)> = vec![
            (
                2,
                Box::new(|body| {
                    body.as_object_mut().expect("an object").remove("aaguid");
                }),
            ),
            (3, Box::new(|body| body["aaguid"] = Value::Null)),
        ];
        for (n, edit) in edits {
            let pk = Passkey::new(n);
            let change = add_change(&mut client, &pk);
            let res = post_edited(&app, &jar, &client, &change, edit).await;
            assert_eq!(res.status, StatusCode::OK, "{n}: {}", res.text());
            took(&app, &mut client, &change);
            let rows = prf_rows(&app, client.ids.account_id).await;
            let row = rows.iter().find(|r| r.0 == pk.method_id).expect("the row");
            assert_eq!(row.5, None, "{n}");
        }
        let listed = vault_get(&app, &jar, PATH).await.json();
        assert_eq!(
            listed["methods"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m.get("aaguid").is_some())
                .count(),
            1,
            "only the zero one is listed with an AAGUID"
        );

        // Ferret's own AAGUID, and one of another length, are refused with
        // nothing written.
        let before = snapshot(&app, &client).await;
        let change = add_change(&mut client, &Passkey::new(4));
        for (what, value) in [
            ("Ferret's own", hex(&AAGUID)),
            ("15 bytes", "9d".repeat(15)),
            ("17 bytes", "9d".repeat(17)),
            ("upper case", "9D".repeat(16)),
            ("not hex", "zz".repeat(16)),
        ] {
            let res = post_edited(&app, &jar, &client, &change, |body| {
                body["aaguid"] = json!(value);
            })
            .await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{what}: {}",
                res.text()
            );
            assert_eq!(error_of(&res), "bad_request", "{what}");
            nothing_changed(&app, &client, &before).await;
        }
    }

    #[tokio::test]
    async fn the_eleventh_prf_method_is_refused() {
        let (app, mut client, jar, _) = setup(6).await;
        for n in 1..=10 {
            let change = add_change(&mut client, &Passkey::new(n));
            let res = post(&app, &jar, &client, &change).await;
            assert_eq!(res.status, StatusCode::OK, "{n}: {}", res.text());
            took(&app, &mut client, &change);
        }
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 10);
        let before = snapshot(&app, &client).await;
        app.backup_status().take_request();

        let change = add_change(&mut client, &Passkey::new(11));
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", res.text());
        assert_eq!(error_of(&res), "quota_exceeded");
        nothing_changed(&app, &client, &before).await;

        // One removed, one more fits; the cap counts passkeys only, so the
        // password and the recovery wrap are not in it.
        let gone = Passkey::new(3).method_id;
        let removal = remove_change(&mut client, gone);
        let res = delete(&app, &jar, &client, &removal, &gone).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        took(&app, &mut client, &removal);
        let change = add_change(&mut client, &Passkey::new(11));
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 10);

        // Another account has its own ten.
        let mut other = client_account(&app, 7).await;
        let session = client_session(&app, &other, SessionScope::Full, 5).await;
        let change = add_change(&mut other, &Passkey::new(21));
        let res = post(&app, &session.jar, &other, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    }

    #[tokio::test]
    async fn the_manifest_rev_must_be_the_next_one() {
        let (app, mut client, jar, _) = setup(8).await;
        let before = snapshot(&app, &client).await;
        let change = add_change(&mut client, &Passkey::new(1));
        for rev in [0u64, 1, 3, 1 << 40] {
            let res = post_edited(&app, &jar, &client, &change, |body| {
                body["manifest"]["rev"] = json!(rev);
            })
            .await;
            assert_eq!(res.status, StatusCode::CONFLICT, "{rev}: {}", res.text());
            assert_eq!(error_of(&res), "write_conflict", "{rev}");
            nothing_changed(&app, &client, &before).await;
        }
        // An envelope that is no manifest: 422, and nothing written.
        let res = post_edited(&app, &jar, &client, &change, |body| {
            body["manifest"]["envelope"] = json!("09".repeat(64));
        })
        .await;
        assert_eq!(
            res.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            res.text()
        );
        assert_eq!(error_of(&res), "unsupported_envelope");
        nothing_changed(&app, &client, &before).await;
        // The next one goes through, and a removal is held to the same rule.
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        took(&app, &mut client, &change);
        let after_add = snapshot(&app, &client).await;
        let id = Passkey::new(1).method_id;
        let removal = remove_change(&mut client, id);
        let body = edited(&removal, |body| body["manifest"]["rev"] = json!(2));
        let res = send_body(
            &app,
            &jar,
            &client,
            removal.op,
            Method::DELETE,
            &remove_path(&id),
            body,
        )
        .await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &after_add).await;
    }

    #[tokio::test]
    async fn removing_needs_the_id_in_the_body_and_the_url_alike() {
        let (app, mut client, jar, _) = setup(9).await;
        let (one, two) = (Passkey::new(1), Passkey::new(2));
        for pk in [&one, &two] {
            let change = add_change(&mut client, pk);
            assert_eq!(
                post(&app, &jar, &client, &change).await.status,
                StatusCode::OK
            );
            took(&app, &mut client, &change);
        }
        let before = snapshot(&app, &client).await;
        let removal = remove_change(&mut client, one.method_id);

        // The URL names the other passkey: the proof would be for the body's.
        let res = delete(&app, &jar, &client, &removal, &two.method_id).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
        // The body names the other one.
        let res = send_body(
            &app,
            &jar,
            &client,
            removal.op,
            Method::DELETE,
            &remove_path(&one.method_id),
            edited(&removal, |body| {
                body["method_id"] = json!(hex16::encode(&two.method_id));
            }),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
        // The body has no id, or one that is not 32 lower-case hex characters.
        for value in [
            None,
            Some(json!(hex16::encode(&one.method_id).to_uppercase())),
            Some(json!("abc")),
            Some(json!(12)),
        ] {
            let res = send_body(
                &app,
                &jar,
                &client,
                removal.op,
                Method::DELETE,
                &remove_path(&one.method_id),
                edited(&removal, |body| match &value {
                    Some(value) => body["method_id"] = value.clone(),
                    None => {
                        body.as_object_mut().expect("an object").remove("method_id");
                    }
                }),
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{value:?}: {}",
                res.text()
            );
            nothing_changed(&app, &client, &before).await;
        }
        // A URL that holds no id: 400 before a nonce is looked at.
        for path in [format!("{PATH}/zz"), format!("{PATH}/{}", "AB".repeat(16))] {
            let res = send_body(
                &app,
                &jar,
                &client,
                removal.op,
                Method::DELETE,
                &path,
                removal.body.clone(),
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{path}: {}",
                res.text()
            );
            nothing_changed(&app, &client, &before).await;
        }
        // An id the account does not have, in both places: 404.
        let unknown = id16(0xee, 9);
        let res = send_body(
            &app,
            &jar,
            &client,
            removal.op,
            Method::DELETE,
            &remove_path(&unknown),
            edited(&removal, |body| {
                body["method_id"] = json!(hex16::encode(&unknown))
            }),
        )
        .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
        // An id of another account's passkey is as unknown.
        let mut theirs = client_account(&app, 10).await;
        let theirs_session = client_session(&app, &theirs, SessionScope::Full, 6).await;
        let change = add_change(&mut theirs, &Passkey::new(5));
        assert_eq!(
            post(&app, &theirs_session.jar, &theirs, &change)
                .await
                .status,
            StatusCode::OK
        );
        app.backup_status().take_request();
        let foreign = Passkey::new(5).method_id;
        let res = send_body(
            &app,
            &jar,
            &client,
            removal.op,
            Method::DELETE,
            &remove_path(&foreign),
            edited(&removal, |body| {
                body["method_id"] = json!(hex16::encode(&foreign))
            }),
        )
        .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
        assert_eq!(prf_rows(&app, theirs.ids.account_id).await.len(), 1);

        // The removal as made goes through: the row and the entry are gone.
        let res = delete(&app, &jar, &client, &removal, &one.method_id).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        assert_eq!(res.json(), json!({"seq": 4}));
        let rows = prf_rows(&app, client.ids.account_id).await;
        assert_eq!(
            rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            [two.method_id]
        );
        let after = snapshot(&app, &client).await;
        assert_eq!(after.manifest_envelope, removal.sealed.envelope);
        assert_eq!((after.manifest_rev, after.vault_seq), (4, 4));
        // Gone for good: the same removal again is a revision behind.
        let res = delete(&app, &jar, &client, &removal, &one.method_id).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
    }

    #[tokio::test]
    async fn password_and_recovery_cannot_be_removed_here() {
        let (app, mut client, jar, _) = setup(11).await;
        let pk = Passkey::new(1);
        let change = add_change(&mut client, &pk);
        assert_eq!(
            post(&app, &jar, &client, &change).await.status,
            StatusCode::OK
        );
        took(&app, &mut client, &change);
        let before = snapshot(&app, &client).await;
        let removal = remove_change(&mut client, pk.method_id);

        // The core refuses to make such a change, so the body is edited.
        for (what, id) in [("password", id16(0xc1, 11)), ("recovery", id16(0xc2, 11))] {
            let res = send_body(
                &app,
                &jar,
                &client,
                removal.op,
                Method::DELETE,
                &remove_path(&id),
                edited(&removal, |body| {
                    body["method_id"] = json!(hex16::encode(&id))
                }),
            )
            .await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{what}: {}",
                res.text()
            );
            nothing_changed(&app, &client, &before).await;
        }
        // And not as an addition of a wrap of another type.
        let add = add_change(&mut client, &Passkey::new(2));
        for method_type in [1, 2, 4] {
            let res = post_edited(&app, &jar, &client, &add, |body| {
                body["method_type"] = json!(method_type);
            })
            .await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{method_type}: {}",
                res.text()
            );
            nothing_changed(&app, &client, &before).await;
        }
        assert_eq!(snapshot(&app, &client).await.wraps.len(), 3);
    }

    #[tokio::test]
    async fn the_fields_of_an_addition_are_held_to_their_rules() {
        let (app, mut client, jar, _) = setup(12).await;
        let before = snapshot(&app, &client).await;
        let change = add_change(&mut client, &Passkey::new(1));
        let wrap = hex(&change.wrap.as_ref().expect("a wrap").wrap);
        let cases: Vec<(&str, Edit)> = vec![
            ("generation 2", Box::new(|b| b["kek_generation"] = json!(2))),
            ("generation 0", Box::new(|b| b["kek_generation"] = json!(0))),
            (
                "a short wrap",
                Box::new(move |b| b["wrap"] = json!(wrap[2..].to_string())),
            ),
            ("an empty wrap", Box::new(|b| b["wrap"] = json!(""))),
            (
                "no credential",
                Box::new(|b| b["credential_id"] = json!("")),
            ),
            (
                "a credential of 1025 bytes",
                Box::new(|b| b["credential_id"] = json!("ab".repeat(1025))),
            ),
            (
                "a zero salt",
                Box::new(|b| b["prf_salt"] = json!("00".repeat(32))),
            ),
            (
                "a short salt",
                Box::new(|b| b["prf_salt"] = json!("11".repeat(31))),
            ),
            (
                "a zero method id",
                Box::new(|b| b["method_id"] = json!("00".repeat(16))),
            ),
            (
                "an extra field",
                Box::new(|b| b["name"] = json!("Work laptop")),
            ),
            (
                "a missing wrap",
                Box::new(|b| {
                    b.as_object_mut().expect("an object").remove("wrap");
                }),
            ),
            (
                "a method type as text",
                Box::new(|b| b["method_type"] = json!("3")),
            ),
        ];
        for (what, edit) in cases {
            let res = post_edited(&app, &jar, &client, &change, edit).await;
            assert_eq!(
                res.status,
                StatusCode::BAD_REQUEST,
                "{what}: {}",
                res.text()
            );
            assert_eq!(error_of(&res), "bad_request", "{what}");
            nothing_changed(&app, &client, &before).await;
        }
        // A credential of 1024 bytes is the longest that is taken.
        let res = post_edited(&app, &jar, &client, &change, |b| {
            b["credential_id"] = json!("ab".repeat(1024));
        })
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    }

    #[tokio::test]
    async fn a_device_token_cannot_add_or_remove_a_method() {
        let app = device_app().await;
        let client = client_account(&app, 13).await;
        let mut device = DeviceClient::new(1);
        let res = device
            .sign_in(
                &app,
                "client13@example.com",
                crate::support::accounts::CLIENT_PASSWORD,
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let before = snapshot(&app, &client).await;
        let id = Passkey::new(1).method_id;
        for (method, path) in [
            (Method::POST, PATH.to_string()),
            (Method::DELETE, remove_path(&id)),
        ] {
            let req = device
                .token_req(&app, method.clone(), &path)
                .json(&json!({}));
            let res = device.send(&app, req).await;
            assert_eq!(
                res.status,
                StatusCode::UNAUTHORIZED,
                "{method} {path}: {}",
                res.text()
            );
            assert_eq!(error_of(&res), "unauthorized");
        }
        assert_eq!(snapshot(&app, &client).await, before);
        // The token still reads the list.
        let res = device
            .send(&app, device.token_req(&app, Method::GET, PATH))
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    }

    #[tokio::test]
    async fn only_a_full_session_can_add_or_remove_a_method() {
        let app = app().await;
        let mut client = client_account(&app, 14).await;
        let before = snapshot(&app, &client).await;
        let change = add_change(&mut client, &Passkey::new(1));
        for scope in [
            SessionScope::AccountReset,
            SessionScope::Pending2fa,
            SessionScope::Unverified,
        ] {
            let session = client_session(&app, &client, scope, 7).await;
            // A reset session may ask for a nonce; the others send one that
            // was never issued. None of them gets anywhere.
            let res = if scope == SessionScope::AccountReset {
                post(&app, &session.jar, &client, &change).await
            } else {
                send_signed(
                    &app,
                    &session.jar,
                    Method::POST,
                    PATH,
                    &[1; 32],
                    &[2; 64],
                    change.body.clone(),
                )
                .await
            };
            assert!(
                matches!(res.status.as_u16(), 401 | 403),
                "{scope:?}: {}",
                res.text()
            );
            nothing_changed(&app, &client, &before).await;
        }
        // No session at all.
        let res = send_signed(
            &app,
            &Jar::default(),
            Method::POST,
            PATH,
            &[1; 32],
            &[2; 64],
            change.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
    }

    #[tokio::test]
    async fn a_session_that_ended_cannot_add_or_remove_a_method() {
        let (app, mut client, jar, sid) = setup(18).await;
        let pk = Passkey::new(1);
        let change = add_change(&mut client, &pk);
        assert_eq!(
            post(&app, &jar, &client, &change).await.status,
            StatusCode::OK
        );
        took(&app, &mut client, &change);
        let removal = remove_change(&mut client, pk.method_id);
        let again = add_change(&mut client, &Passkey::new(2));
        let before = snapshot(&app, &client).await;
        let at = i64::try_from(app.clock.now_unix()).expect("a time");
        app.state
            .vault_db
            .with_conn(move |conn| Ok(ferret_server::auth::session::revoke(conn, &sid, at)?))
            .await
            .expect("the session ends");
        assert!(ended(&app, sid).await);
        let res = send_signed(
            &app,
            &jar,
            Method::POST,
            PATH,
            &[1; 32],
            &[2; 64],
            again.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        let res = send_signed(
            &app,
            &jar,
            Method::DELETE,
            &remove_path(&pk.method_id),
            &[1; 32],
            &[2; 64],
            removal.body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
    }

    #[tokio::test]
    async fn adding_and_removing_ask_for_a_backup_and_end_no_session() {
        let (app, mut client, jar, this) = setup(15).await;
        let user = client.ids.user_id;
        let laptop = issue(&app, user, Origin::Vault, SessionScope::Full, 2).await;
        let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 3).await;
        let child = issue(&app, user, Origin::Admin, SessionScope::Full, 4)
            .await
            .sid;
        app.state
            .vault_db
            .with_conn(move |conn| Ok(set_parent(conn, &child, &this)?))
            .await
            .expect("a parent");
        let mut this_stream = app.events(&jar).await;
        this_stream.event("hello", SECOND).await;
        let mut laptop_stream = app.events(&laptop.jar).await;
        laptop_stream.event("hello", SECOND).await;
        let mut revocations = app.sync_events().subscribe_revocations();

        // A refused addition asks for no backup.
        let change = add_change(&mut client, &Passkey::new(1));
        let res = post_edited(&app, &jar, &client, &change, |b| {
            b["kek_generation"] = json!(5)
        })
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert!(!app.backup_status().has_request());

        for step in 0..2u8 {
            let (res, seq) = if step == 0 {
                (post(&app, &jar, &client, &change).await, 2)
            } else {
                took(&app, &mut client, &change);
                let id = Passkey::new(1).method_id;
                let removal = remove_change(&mut client, id);
                (delete(&app, &jar, &client, &removal, &id).await, 3)
            };
            assert_eq!(res.status, StatusCode::OK, "{step}: {}", res.text());
            assert_eq!(res.json(), json!({"seq": seq}));
            assert_eq!(app.backup_status().take_request(), Some("unlock_methods"));
            // Every stream of the vault hears of the new manifest, and goes on.
            for stream in [&mut this_stream, &mut laptop_stream] {
                let sync = stream.event("sync", SECOND).await;
                assert_eq!(sync["seq"], json!(seq), "{sync}");
                stream.quiet(Duration::from_millis(300)).await;
            }
            for sid in [this, laptop.sid, admin.sid, child] {
                assert!(!ended(&app, sid).await, "no session ends");
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(300), revocations.recv())
                    .await
                    .is_err(),
                "no session or device is announced as ended"
            );
            // The session is still fresh: a change does not use the
            // re-authentication up.
            let res = vault_get(&app, &laptop.jar, PATH).await;
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        }
    }

    #[tokio::test]
    async fn write_conflict_when_the_methods_changed_meanwhile() {
        let (app, mut client, jar, _) = setup(16).await;
        // Two additions made from the same manifest: both would be revision 2.
        let first = add_change(&mut client, &Passkey::new(1));
        let second = add_change(&mut client, &Passkey::new(2));
        let first_nonce = nonce_for(&app, &jar).await;
        let second_nonce = nonce_for(&app, &jar).await;
        let first_proof = first.sign(&client.vault, &first_nonce).expect("a proof");
        let second_proof = second.sign(&client.vault, &second_nonce).expect("a proof");
        let (a, b) = tokio::join!(
            send_signed(
                &app,
                &jar,
                Method::POST,
                PATH,
                &first_nonce,
                &first_proof,
                first.body.clone()
            ),
            send_signed(
                &app,
                &jar,
                Method::POST,
                PATH,
                &second_nonce,
                &second_proof,
                second.body.clone()
            ),
        );
        let mut statuses = [a.status.as_u16(), b.status.as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409], "{a:?} {b:?}");
        let loser = if a.status == StatusCode::OK { &b } else { &a };
        assert_eq!(error_of(loser), "write_conflict");
        let winner = if a.status == StatusCode::OK {
            &first
        } else {
            &second
        };
        let after = snapshot(&app, &client).await;
        assert_eq!(after.manifest_envelope, winner.sealed.envelope);
        assert_eq!((after.manifest_rev, after.vault_seq), (2, 2));
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 1);

        // A removal made before the other change is a revision behind.
        took(&app, &mut client, winner);
        let id = if a.status == StatusCode::OK {
            Passkey::new(1).method_id
        } else {
            Passkey::new(2).method_id
        };
        let removal = remove_change(&mut client, id);
        let other = add_change(&mut client, &Passkey::new(3));
        assert_eq!(
            post(&app, &jar, &client, &other).await.status,
            StatusCode::OK
        );
        let res = delete(&app, &jar, &client, &removal, &id).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
        assert_eq!(error_of(&res), "write_conflict");
        assert_eq!(prf_rows(&app, client.ids.account_id).await.len(), 2);
    }

    // ------------------------------------------------------------------ log

    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Sink {
        type Writer = Sink;

        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }

    fn log_sink() -> Sink {
        static SINK: OnceLock<Sink> = OnceLock::new();
        SINK.get_or_init(|| {
            let sink = Sink::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(sink.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .finish();
            tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
            sink
        })
        .clone()
    }

    #[tokio::test]
    async fn a_change_leaves_one_line_and_nothing_that_names_the_passkey() {
        let sink = log_sink();
        let (app, mut client, jar, _) = setup(17).await;
        let pk = Passkey::new(1);
        let change = add_change(&mut client, &pk);
        let mark = sink.0.lock().unwrap().len();
        let res = post(&app, &jar, &client, &change).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        took(&app, &mut client, &change);
        let removal = remove_change(&mut client, pk.method_id);
        let res = delete(&app, &jar, &client, &removal, &pk.method_id).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        let text = String::from_utf8(sink.0.lock().unwrap()[mark..].to_vec()).unwrap();
        assert!(text.contains("a passkey unlock method was added"), "{text}");
        assert!(
            text.contains("a passkey unlock method was removed"),
            "{text}"
        );
        let wrap = &change.wrap.as_ref().expect("a wrap").wrap;
        for value in [
            wrap.as_slice(),
            pk.credential_id.as_slice(),
            pk.prf_salt.as_slice(),
            pk.aaguid.as_slice(),
            pk.method_id.as_slice(),
            change.sealed.envelope.as_slice(),
            change.sealed.tag.as_slice(),
        ] {
            for form in [
                b64url::encode(value),
                hex(value),
                format!("{value:?}")
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
            ] {
                assert!(!text.contains(&form), "the log holds {form:.40}");
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        ferret_core::testing::hex_encode(bytes)
    }
}

#[cfg(not(feature = "quick-unlock"))]
mod without_routes {
    use axum::http::{Method, StatusCode};
    use ferret_server_auth::SessionScope;

    use crate::support::accounts::{client_account, client_session, send_signed};
    use crate::support::{Jar, PEER, TestApp};
    use ferret_server::http::proxy_guard::ProxyList;

    #[tokio::test]
    async fn the_routes_are_absent_without_quick_unlock() {
        let proxies =
            ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("proxies");
        let app = TestApp::builder().proxies(proxies).build().await;
        let client = client_account(&app, 1).await;
        let issued = client_session(&app, &client, SessionScope::Full, 1).await;
        let jar: Jar = issued.jar;
        let id = "11".repeat(16);
        // The list is there; a POST on its path has no handler (405) and a
        // DELETE on the path of a method has no route (404). Neither is a
        // sign-in or a proof question: nothing runs.
        for (method, path, expected) in [
            (Method::POST, "/api/vault/unlock-methods".to_string(), 405),
            (
                Method::DELETE,
                format!("/api/vault/unlock-methods/{id}"),
                404,
            ),
        ] {
            let res = send_signed(
                &app,
                &jar,
                method.clone(),
                &path,
                &[1; 32],
                &[2; 64],
                b"{}".to_vec(),
            )
            .await;
            assert_eq!(
                res.status.as_u16(),
                expected,
                "{method} {path}: {}",
                res.text()
            );
        }
        let res = send_signed(
            &app,
            &jar,
            Method::GET,
            "/api/vault/unlock-methods",
            &[1; 32],
            &[2; 64],
            vec![],
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    }
}
