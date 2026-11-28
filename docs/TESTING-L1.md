# Testing several accounts (invitations, the Users page and Activity)

This milestone lets one server hold more than one account. The first administrator is still made with the setup token;
every later account is made from an **invitation link** that an administrator makes on the **Users** page of the admin
pages (`/settings/accounts`). The invited person opens the link, chooses a master password, gets a secret key and the
emergency sheet, and has a vault of her own, set up as the first one is. The administrator sees each account's e-mail,
devices and space (never what is in a vault), and can make a one-time sign-in code, disable and enable an account, sign it
out everywhere and delete it after a disable and a later backup. Every one of those actions is written to the **account
log**, which the person sees on the **Activity** page of the web vault and, at an unlock, as a notice. This file lists what
is tested automatically, what is not, and how a person checks the rest by hand (about an hour and a half).
`docs/design/phase-1-security-design.md` (sections 1, 2.3, 2.5, 4.2, 6.3, 8.2, 8.8 and 11, "Several accounts") says what
the feature promises; `docs/OPERATIONS.md` ("Accounts, invitations and the Users page") is the operator's view.

All data on the test instance is throwaway test data. Use made-up names, e-mail addresses and passwords only.

## Automated tests

| What | What it checks | Command |
| --- | --- | --- |
| Server (S, S-full) | The schema and the upgrade from 0.12.x, the wire forms, registration with an invitation, the account log, the sign-in codes, the Users page and its actions, the restore's sweep, the isolation matrix, the stream limit and pre-login with three accounts (the files below) | `scripts/lanbox.sh test -p ferret-server --locked` (with and without `--features e2e-clock,quick-unlock,passkey-import`), plus `fmt` and `clippy -D warnings` |
| Web vault unit tests and type check (W) | The invitation in the address, the join page and its reload, `checkInvite`, `register()` with an invitation, Activity, the notice and its mark, the texts | `scripts/lanbox-web.sh --wasm tree unit` |
| The web vault's end-to-end suite (W-full) | Every web vault spec against a stack, in Chromium, Firefox and WebKit | `scripts/lanbox-web.sh --wasm tree` |
| The several-accounts step of the gate (E-L1) | Specs 01, 32, 33 and 34 below, in each browser on a fresh stack | `scripts/lanbox-ferret-e2e-gate.sh l1`, then `scripts/lanbox-ferret-test.sh e2e-down` |
| The extension (XL1), Release and ESR, MV2 and MV3 | Spec 76 below: an invited account in an extension profile of its own | `scripts/lanbox-ext.sh e2e --grep 'second_account\|its_device_is_listed' --wasm tree [--channel release\|esr] [--manifest mv2\|mv3]` |
| Extension unit tests (X) | Among them the text of the design that this milestone pins (`specText.test.mjs`); the extension's own code is unchanged | `scripts/lanbox-ext.sh unit --wasm tree` |
| The upgrade drill (UP) | The released 0.12.1 image by digest (and its signature, with cosign 3), data put in with it, a backup, then this build on the same data while the browser and the device stay open | `scripts/lanbox-ferret-test.sh upgrade-drill v0.12.1` |
| The stack for real data | The open-file limit of the server and the cosign 3 rule of `scripts/ferret-home.sh up` (among the other checks of that file) | `scripts/check-ferret-home-stack.sh`, `shellcheck` on the scripts |

The branch ran its web and extension suites with `--wasm tree`; delivery 1 changes nothing in the core, the WASM binding or
the extension, so the pinned package of the release gives the same result.

### The server tests

| File | Tests | What they show |
| --- | --- | --- |
| `schema.rs` | `migration_0010_keeps_every_0_12_row`, `the_0_12_schema_still_matches_u3_sql` and the golden `l1.sql` | A 0.12.x database (Ferret's migrations 0001 to 0009, the kit's seven core migrations and the kit's 0.12 tables filled) runs `kit/0007_invites.sql` and `0010_accounts.sql` and keeps every row |
| `restore.rs` | `a_0_12_backup_set_restores_into_this_build`, `a_restore_revokes_pending_invitations_and_logs_it_for_every_account` | A set made by 0.12 restores into this build; a restore never wakes a revoked link and writes `server_restored` for every account |
| `invites.rs` | `an_invited_person_registers_and_gets_a_viewer_account_with_a_vault_and_a_session`, `the_invitation_works_once_even_when_two_finish_at_once`, `a_revoked_or_expired_invitation_is_refused_at_start_and_at_finish`, `unknown_used_revoked_and_expired_invitations_answer_alike`, `a_taken_email_is_email_taken_only_with_a_valid_invitation`, `starts_per_invitation_are_capped`, `the_start_count_holds_ten_an_hour_and_a_full_table_drops_the_oldest`, `one_invitee_cannot_wipe_another_invitees_waiting_registration`, `send_again_lets_the_invitee_start_again_with_the_same_email`, `a_pending_holder_holds_an_email_only_while_its_invitation_is_pending`, `invite_check_answers_expiry_and_inviter_and_is_throttled_per_address`, `the_invitation_token_never_reaches_the_log`, `the_new_account_signs_in_recovers_with_its_rk_and_gets_a_device` and more | Registration with an invitation, its answers in order, the cap on `email_taken`, and the hold of an e-mail by another pending invitation |
| `account_log.rs`, `redeem.rs`, `cli_codes.rs` | `each_account_sees_only_its_own_events`, `a_user_keeps_at_most_1000_events`, `a_reset_session_a_device_token_and_the_admin_listener_cannot_read_events`, `an_event_holds_no_code_and_no_token`, `cli_code_writes_an_event_and_a_failed_write_revokes_the_code` | The log, who may read it, and the sign-in code's two events (made, redeemed), from the page and from the command |
| `admin_accounts.rs` | `the_users_page_lists_every_account_with_the_ferret_columns`, `the_page_never_shows_a_vault_secret`, `the_kit_users_routes_are_closed`, `an_invitation_link_is_shown_once_with_no_store_and_points_at_the_vault_fragment`, `fifty_pending_invitations_is_the_limit`, `a_sign_in_code_uses_the_confirmation_up`, `no_action_works_on_your_own_account_or_an_admin`, `the_hand_over_to_the_admin_pages_is_for_admins_only`, `disabling_ends_sessions_devices_and_codes_at_once_and_closes_streams`, `a_disabled_account_answers_sign_in_like_an_unknown_one`, `enabling_needs_a_fresh_reauth_and_is_logged`, `delete_needs_disable_a_later_good_backup_reauth_and_the_typed_email`, `delete_never_touches_another_account`, `every_action_and_its_event_commit_together`, `the_server_command_cannot_delete_an_account`, `the_prelogin_policy_follows_a_disabled_enabled_or_deleted_account_at_once` and more | The Users page, which actions need the master password again, the rule that an action and its event commit together, and the two-step deletion |
| `accounts_matrix.rs` | `accounts_matrix_no_route_crosses_accounts`, `a_challenge_of_one_account_does_not_sign_for_another`, `a_write_in_one_vault_wakes_only_its_own_streams`, `revoke_all_and_a_redeemed_code_of_b_leave_a_alone` | Every route of the vault listener, sent by one account with the ids of another: nothing of the other account is read, written, revoked or woken |
| `login.rs`, `events.rs` | `known_and_unknown_names_answer_alike_with_three_accounts`, `the_total_cap_holds` | Pre-login with three real accounts; 1 024 streams on the server (2 per device, 40 per account) |

### The end-to-end specs

| Spec | Tests | What it shows |
| --- | --- | --- |
| `32-invite` | `an_invited_person_joins_gets_the_sheet_and_signs_in_again`, `a_used_link_says_so_before_any_password_is_typed`, `the_invite_never_appears_in_history_storage_or_a_request_url` | The join page, the emergency sheet, a used link said before any password, and the token in no history entry, stored data or request address |
| `33-two-accounts` | `join_in_a_browser_that_remembers_another_account`, `two_accounts_in_one_browser_never_see_each_other`, `an_invited_account_adds_a_passkey_and_opens_the_vault_with_it` | Two accounts in one browser profile keep the list, the sync, the local rows, the outbox and the Activity marks apart, also when another tab switches the account; an invited account's passkey unlock |
| `34-admin-accounts` | `an_admin_code_shows_in_the_users_log_and_as_a_notice`, `disable_and_sign_out_everywhere_end_the_users_tabs_and_devices` | A sign-in code made on the Users page is in the account's Activity and its notice; disable and sign out everywhere end the account's browsers and devices |
| `06-admin`, `06-admin-signout` | as before | The admin pages, now through `/settings/accounts` |
| `phase-upgrade-before`, `phase-upgrade-after` | `the_release_gets_an_account_with_everything_in_it`, `its_device_token_still_renews_without_a_new_sign_in`, `its_passkey_method_still_unlocks`, `after_the_upgrade_the_first_account_unlocks_with_everything_there`, `the_pin_rule_is_kept`, `the_first_account_can_invite_at_once` and more | The upgrade from 0.12.1: items, a folder, a one-time password, the trash, a stricter PIN rule, a device with tokens and a passkey unlock method survive, and the first account invites a second one |
| `76-second-account.e2e` (extension) | `a_second_account_signs_in_syncs_and_fills_in_its_own_profile`, `its_device_is_listed_for_it_only` | An invited account signs the extension in, syncs and fills in a profile of its own; its device is listed for it only |

## Not tested, and known limits

- **The steps that need a fresh master password check run in Chromium.** WebKit stops on the redirect to the vault's
  password check under Playwright, so `32`, `33` and `34` do the administrator's part in Chromium and the invitee's part in
  each browser. The passkey test of `33` runs where the browser has a virtual authenticator (it is skipped in Firefox and
  WebKit).
- **An invitation's expiry is not aged by the end-to-end clock.** The kit's invitation runs out on the database's own clock
  (SQLite `datetime('now')`); the server tests age the row with SQL instead.
- **Two people at once on a real network** are checked by hand only (below).
- **The open-file limit** is checked in the compose file of the stack for real data and by hand on the host (check 8); no
  test opens 1 024 streams at once.
- The known limits of delivery 1 are in § 8.8 of the design ("Several accounts"): among them that a link is bound to no
  e-mail address, that `email_taken` tells the holder of a valid link that an address is taken or held by another
  invitee's waiting registration (and the web vault's text then says that an account exists), that the waiting
  registrations share one cap of 64, that a restore brings the accounts back as the set holds them, that the account log's
  answer names no account, and that one extension profile holds one account.

## Checks by hand on a test instance

**You need:**

- a test instance built from the commit under test, behind your reverse proxy at `https://vault.example.test` (the vault)
  and `https://admin.example.test` (the admin pages); the names are placeholders, use your own. Take a backup of it, and
  check the set, before you start;
- your own account on it (the administrator) with items, folders, one-time codes, a device with the extension, a PIN and a
  passkey unlock method, as after the earlier milestones;
- a second computer, or a second Firefox profile, for the invited person, with the extension installed;
- a printer or a PDF printer for the emergency sheet;
- a shell on the server for `ferret sign-in-code issue` (`docs/OPERATIONS.md`, "The one-time sign-in code").

Steps marked ⚠️ change an account. Do them on a test account that you invite for the purpose, never on your own.

### 1. Before: everything of yours is there (about 10 minutes)

1. After the upgrade, unlock the web vault.
   *Expected:* the items, the folders and the one-time codes are there.
2. Open the extension.
   *Expected:* it is still signed in; the PIN, the passkey unlock and filling a login work.
3. Open Devices in the web vault.
   *Expected:* the same devices as before the upgrade.

### 2. Invite (about 10 minutes)

1. In the admin pages open Settings, Users.
   *Expected:* your account with its e-mail, when it was made and last signed in, its devices, items, space, two-factor
   ("off", with a line that says why), "Active" and "Admin". No PIN column, and no button for your own account.
2. Press "Invite someone".
   *Expected:* without a recent confirmation, the page sends you to confirm it is you with the master password and comes back.
   Then "Invitation made" with the link, a warning that it is shown once, and a copy button. The link has the form
   `https://vault.example.test/vault/setup#invite=<43 letters and digits>`. Copy it.
3. Reload the page.
   *Expected:* the link is not shown again; "Open invitations" lists it with when it was made, by whom, and that it runs
   out in 7 days.
4. Make a second link, press "Revoke" on it (a confirmation, no master password), and open it in a private window.
   *Expected:* the join page says that the invitation link no longer works (used, withdrawn or run out) before it asks for
   anything.

### 3. The invited person makes an account (about 20 minutes, on the second computer)

1. Open the link.
   *Expected:* "Join Ferret on <host>", with who invited her and until when the link works, and only once. The address bar
   no longer shows the token.
2. Reload the page.
   *Expected:* the page says that it no longer has the invitation link and to open the link again; there is no field, and
   nothing is sent to the server. Open the link again.
3. Enter an e-mail and a master password, keep the secret key on, and go through the emergency sheet, typing back the
   recovery key and the secret key.
   *Expected:* the account is made and the vault is empty. Print the sheet (both pages).
4. Open the link once more.
   *Expected:* the link no longer works.
5. Install the extension (or use the one on that profile), sign in with the new account, save one login on a test site and
   fill it.
   *Expected:* it works as for the first account.
6. Compare Devices on both accounts.
   *Expected:* each lists only its own browsers and extension.

### 4. The administrator and the log (about 15 minutes)

1. Users page.
   *Expected:* the new account is listed with its devices and space; the invitation is gone from "Open invitations".
2. ⚠️ "Make a sign-in code" on the test account (confirm with your master password when asked).
   *Expected:* "Sign-in code made" with the code once, the address of the recovery page and until when it works; the account
   shows "Sign-in code until …". Make a code for another account, or press "Enable" later: it asks for the master password
   again, because a code uses the confirmation up.
3. On the test account, lock the web vault and unlock it, then open the account menu, Activity.
   *Expected:* at the unlock a notice that an administrator made a sign-in code for the account, with "See activity";
   Activity lists "Sign-in code made" by the administrator with your e-mail. After Activity was shown, the next unlock has
   no notice.
4. ⚠️ "Disable" the test account (a confirmation, no master password).
   *Expected:* "Disabled"; the test account's open vault tab shows at once that its live updates stopped and asks to sign in
   again at its next call; the extension there is signed out. A sign-in with the right master password is refused like a
   wrong one.
5. ⚠️ "Enable" (confirm with your master password).
   *Expected:* "Active" again; the test account signs in again with its master password, and the extension needs a new
   sign-in (a device that the disable revoked stays revoked). Activity shows "Account disabled" and "Account enabled again".
6. ⚠️ "Sign out everywhere" (a confirmation, no master password).
   *Expected:* every browser and device of the test account is signed out; Activity shows "Signed out of every device".
7. Look at your own row.
   *Expected:* no action is offered for your own account.

### 5. A forgotten master password for a new account (about 15 minutes, the test account)

1. ⚠️ Make a sign-in code on the Users page, open the recovery page of the vault (`#/recover`) on the test account's
   computer, type the code, then the recovery key from the sheet and a new master password.
   *Expected:* the vault is there with its items.
2. Activity on the test account.
   *Expected:* "Sign-in code made" (by the administrator) and "Sign-in code used" (by you).
3. ⚠️ On the server, `ferret sign-in-code issue --email <test account> --yes`.
   *Expected:* the code is printed once; the test account's Activity says "By a command on the server".

### 6. Deleting (about 10 minutes, the test account)

1. ⚠️ Look at the test account while it is active.
   *Expected:* there is no "Delete for good"; the text below the list says that an account is deleted in two steps,
   disable first.
2. ⚠️ Disable it.
   *Expected:* the row says that the account stays in the backup sets until they run out (30 days unless set otherwise),
   and that a good backup made after the disable is needed, with "Go to Backup". "Delete for good" is not there yet.
3. On the Backup page, "Take a backup now", and wait until the set is good. Back on the Users page.
   *Expected:* "Delete for good" with a field for the account's e-mail (or a button that asks you to confirm with the master
   password first).
4. ⚠️ Type a wrong e-mail and confirm.
   *Expected:* nothing is deleted; the page says that it is not the account's e-mail.
5. ⚠️ Type the right e-mail and confirm.
   *Expected:* "The account and its vault are deleted"; the account is gone from the list, and a sign-in with its e-mail
   and master password is refused like an unknown name. The server's log has one line with your id, the account's id and the time, and no
   e-mail.

### 7. After: everything of yours is still there (about 5 minutes)

1. Repeat check 1.
   *Expected:* your vault, the extension, the PIN and the passkey unlock as before.

### 8. The host (about 5 minutes, the stack for real data)

1. On the host, `docker exec ferret-home-app cat /proc/1/limits`.
   *Expected:* "Max open files" is 4096 or more.
2. `cosign version` on the machine that runs `scripts/ferret-home.sh up`.
   *Expected:* `GitVersion: v3…`. With cosign 2 the script refuses before it pulls the image, and says that cosign 3 is
   needed.

## Results of a gate run

Keep these lines with the release notes of the run:

| Check | Date | Who | Result |
| --- | --- | --- | --- |
| S-full (default features and the test features) |  |  |  |
| W, W-full (Chromium, Firefox, WebKit) |  |  |  |
| E-L1 (Chromium, Firefox, WebKit) and the whole end-to-end gate |  |  |  |
| XL1, Release and ESR, MV2 and MV3 |  |  |  |
| X (extension unit) |  |  |  |
| UP, `upgrade-drill v0.12.1` |  |  |  |
| `check-ferret-home-stack.sh`, shellcheck |  |  |  |
| Check 1, before |  |  |  |
| Check 2, invite |  |  |  |
| Check 3, a new account |  |  |  |
| Check 4, the administrator and the log |  |  |  |
| Check 5, a forgotten master password |  |  |  |
| Check 6, deleting |  |  |  |
| Check 7, after |  |  |  |
| Check 8, the host |  |  |  |
