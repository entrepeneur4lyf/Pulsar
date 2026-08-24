//! Account-management flow tests for the Pulsar starter kit - request path.
//!
//! These drive the kit's **real** HTTP surface: `pulsar::routes::register()`
//! (the actual `routes!` table, root-prefix `group!("/")` groups, guest /
//! auth / verified middleware) plus the same global middleware stack
//! `bootstrap::register()` installs (logging → session → CSRF → include),
//! served through `suprnova::handle_request` - the framework's in-process
//! request surface. Because `hyper::body::Incoming` cannot be built
//! synthetically, requests travel over an ephemeral loopback socket whose
//! service fn is `handle_request`, exactly like the framework's own
//! integration harnesses (`framework/tests/root_group_redirect.rs`,
//! `auth_http_middleware.rs`).
//!
//! The facade-level suite (`tests/auth_flows.rs`) proves the flow *logic*;
//! this suite proves the *wiring*: route matching through root-prefix groups,
//! session-cookie continuity, CSRF token round-trips, the guest/auth/verified
//! gates, real PATCH/PUT/DELETE verbs (no method spoofing), and the
//! `redirect!("/literal")` → `302 Location: /literal` contract.
//!
//! ## History
//!
//! This surface was broken at framework rev `06b9447f`
//! (`group!("/")` registered unmatchable `//login` patterns; `redirect!`
//! resolved literal paths as route names). Both are fixed upstream as of
//! `95777465` (canonical `join_paths` for group prefixes; literal-shape
//! dispatch in `redirect!`) - this suite is the consumer-side pin on those
//! fixes.
//!
//! ## Serial execution
//!
//! `Mail::fake()` swaps the process-global mail transport and the DB /
//! auth-manager bindings live in the process-global container (the server
//! tasks must see them), so the file is serialized behind the shared
//! `common::TEST_LOCK` (also held by `tests/auth_flows.rs`).

mod common;

use chrono::Utc;
use serde_json::{Value, json};

use suprnova::MustVerifyEmail;
use suprnova::mail::MailFake;

use common::{Client, setup};
use pulsar::models::user::User;

/// Reload a user from the DB by email via the same model surface the kit uses.
async fn reload(email: &str) -> User {
    User::find_by_email(email)
        .await
        .expect("lookup")
        .unwrap_or_else(|| panic!("user {email} exists"))
}

/// Stamp a user verified (seeds the password-reset / profile fixtures in the
/// same already-verified state a click-through produces).
async fn mark_verified(user: &mut User) {
    user.email_verified_at = Some(Utc::now());
    suprnova::eloquent::Model::save(user)
        .await
        .expect("stamp email_verified_at");
}

/// Pull the plaintext token out of the first captured mail whose text body
/// carries a `token=` link.
fn token_from_fake(fake: &MailFake) -> String {
    let captured = fake.captured();
    let msg = captured
        .iter()
        .find(|m| {
            m.text
                .as_deref()
                .is_some_and(|t| t.lines().any(|l| l.contains("token=")))
        })
        .expect("a captured mail with a token link");
    let text = msg.text.as_deref().expect("token mail has a text body");
    let link = text
        .lines()
        .find(|l| l.contains("token="))
        .expect("a line with the token link");
    link.split_once("token=")
        .map(|(_, tail)| tail.trim().to_string())
        .expect("verification link should carry token=")
}

// ============================================================================
// 1. Public homepage over HTTP
// ============================================================================

#[tokio::test]
async fn home_page_exposes_landing_sections() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    let resp = client.get("/").await;

    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("Ship a Suprnova product site"));
    assert!(resp.body.contains("features"));
    assert!(resp.body.contains("capabilities"));
}

// ============================================================================
// 2. Email verification over HTTP: register → gated → verify → dashboard
// ============================================================================

#[tokio::test]
async fn register_then_verify_email_over_http() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    // Acquire a session + CSRF cookie through the guest-gated register page -
    // this also proves the root-prefix `group!("/")` routes match over HTTP.
    let resp = client.get("/register").await;
    assert_eq!(resp.status, 200, "GET /register must render: {}", resp.body);

    // Register. The success path is `redirect!("/dashboard")` - the literal
    // Location pins the framework's literal-redirect dispatch fix.
    let fake = &harness.mail;
    let before = fake.count();
    let resp = client
        .post_json(
            "/register",
            json!({
                "name": "Grace Hopper",
                "email": "grace@pulsar.test",
                "password": "supersecret",
                "password_confirmation": "supersecret",
            }),
        )
        .await;
    assert_eq!(resp.status, 302, "register must redirect: {}", resp.body);
    assert_eq!(resp.location(), "/dashboard");

    // A verification mail was captured for the new address.
    fake.assert_sent_to("grace@pulsar.test");
    assert_eq!(fake.count(), before + 1, "exactly one verification mail");
    let token = token_from_fake(fake);

    // Logged in but unverified: the `verified` gate bounces to the notice.
    let resp = client.get("/dashboard").await;
    assert_eq!(resp.status, 302, "unverified user must not see /dashboard");
    assert_eq!(resp.location(), "/verify-email");

    // The notice itself renders (auth-but-not-verified group).
    let resp = client.get("/verify-email").await;
    assert_eq!(resp.status, 200, "the verify notice must render");

    // Consume the emailed token (public route - the token is the proof).
    let resp = client
        .get(&format!("/verify-email/verify?token={token}"))
        .await;
    assert_eq!(resp.status, 302, "verify must redirect: {}", resp.body);
    assert_eq!(resp.location(), "/dashboard");

    // The stamp persisted, and the gate now opens.
    assert!(
        reload("grace@pulsar.test").await.is_email_verified(),
        "verification must persist email_verified_at"
    );
    let resp = client.get("/dashboard").await;
    assert_eq!(resp.status, 200, "verified user reaches /dashboard");
    assert!(resp.body.contains("Starter kit"));
    assert!(resp.body.contains("Manage profile"));
}

// ============================================================================
// 2. Resend over HTTP: a logged-in unverified user gets a fresh link
// ============================================================================

#[tokio::test]
async fn resend_verification_notification_over_http() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);
    let fake = &harness.mail;

    // Register (logged in, unverified) while keeping the shared fake alive so
    // the resend assertions can compare count deltas on the same transport.
    let resp = client.get("/register").await;
    assert_eq!(resp.status, 200);
    let initial_before = fake.count();
    let resp = client
        .post_json(
            "/register",
            json!({
                "name": "Ada Lovelace",
                "email": "ada@pulsar.test",
                "password": "oldpass1!",
                "password_confirmation": "oldpass1!",
            }),
        )
        .await;
    assert_eq!(resp.status, 302, "register: {}", resp.body);
    assert_eq!(
        fake.count(),
        initial_before + 1,
        "register must capture the initial verification mail"
    );

    // Resend: a fresh link is mailed to the logged-in unverified user.
    let resend_before = fake.count();
    let resp = client
        .post_json("/email/verification-notification", json!({}))
        .await;
    assert_eq!(resp.status, 302, "resend must redirect: {}", resp.body);
    assert_eq!(resp.location(), "/verify-email");
    assert_eq!(
        fake.count(),
        resend_before + 1,
        "resend must capture a fresh mail"
    );
    fake.assert_sent_to("ada@pulsar.test");
    assert!(
        !token_from_fake(fake).is_empty(),
        "the resent link carries a token"
    );
}

// ============================================================================
// 3. Password reset over HTTP (incl. anti-enumeration)
// ============================================================================

#[tokio::test]
async fn password_reset_over_http_with_anti_enumeration() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);
    let fake = &harness.mail;

    // Seed a verified user with a known password.
    let mut ada = User::create("Ada Reset", "ada@x.com", "oldpass1!")
        .await
        .expect("create user");
    mark_verified(&mut ada).await;

    // Acquire session + CSRF on the guest-gated request form.
    let resp = client.get("/forgot-password").await;
    assert_eq!(resp.status, 200, "GET /forgot-password must render");

    // Known email → a reset mail is captured.
    let known_before = fake.count();
    let resp = client
        .post_json("/forgot-password", json!({ "email": "ada@x.com" }))
        .await;
    assert_eq!(resp.status, 302, "send-link must redirect: {}", resp.body);
    assert_eq!(resp.location(), "/forgot-password");
    fake.assert_sent_to("ada@x.com");
    assert_eq!(fake.count(), known_before + 1);
    let token = token_from_fake(fake);

    // Unknown email → NO new mail, and the *same* neutral redirect
    // (anti-enumeration: the wire response is indistinguishable).
    let unknown_before = fake.count();
    let resp = client
        .post_json("/forgot-password", json!({ "email": "nobody@x.com" }))
        .await;
    assert_eq!(resp.status, 302, "unknown email gets the same 302");
    assert_eq!(resp.location(), "/forgot-password");
    assert_eq!(
        fake.count(),
        unknown_before,
        "unknown email must send nothing"
    );

    // The reset form renders with the token threaded through.
    let resp = client.get(&format!("/reset-password?token={token}")).await;
    assert_eq!(resp.status, 200, "GET /reset-password must render");

    // Complete the reset → 302 /login.
    let resp = client
        .post_json(
            "/reset-password",
            json!({
                "token": token,
                "password": "newpass1!",
                "password_confirmation": "newpass1!",
            }),
        )
        .await;
    assert_eq!(resp.status, 302, "reset must redirect: {}", resp.body);
    assert_eq!(resp.location(), "/login");

    // The success flash survives the redirect: the /login landing's page
    // object (embedded as JSON in the data-page script tag) carries it
    // under `flash.success`.
    let resp = client.get("/login").await;
    assert_eq!(resp.status, 200, "GET /login must render after reset");
    assert!(
        resp.body.contains(
            r#""flash":{"success":"Your password has been reset. Log in with your new password."}"#
        ),
        "login landing must carry the success flash in its page object: {}",
        resp.body
    );

    // Flash is one-shot: a second visit no longer carries it.
    let resp = client.get("/login").await;
    assert_eq!(resp.status, 200, "second GET /login must render");
    assert!(
        !resp.body.contains("Your password has been reset."),
        "success flash must not survive a second request: {}",
        resp.body
    );

    // The old password no longer logs in…
    let resp = client
        .post_json(
            "/login",
            json!({ "email": "ada@x.com", "password": "oldpass1!" }),
        )
        .await;
    assert_eq!(
        resp.status, 422,
        "old password must be rejected after reset"
    );
    assert!(
        resp.body
            .contains("These credentials do not match our records."),
        "rejection rides the validation envelope: {}",
        resp.body
    );

    // …and the new one does (literal redirect pin: Location is /dashboard).
    let resp = client
        .post_json(
            "/login",
            json!({ "email": "ada@x.com", "password": "newpass1!" }),
        )
        .await;
    assert_eq!(resp.status, 302, "new password must log in: {}", resp.body);
    assert_eq!(resp.location(), "/dashboard");
}

// ============================================================================
// 4. Profile over HTTP: PATCH / PUT / DELETE with real verbs
// ============================================================================

#[tokio::test]
async fn profile_update_password_and_delete_over_http() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    // Seed a verified user and log in through the real login flow.
    let mut user = User::create("Edsger", "edsger@x.com", "oldpass1!")
        .await
        .expect("create user");
    mark_verified(&mut user).await;

    let resp = client.get("/login").await;
    assert_eq!(resp.status, 200, "GET /login must render");
    let resp = client
        .post_json(
            "/login",
            json!({ "email": "edsger@x.com", "password": "oldpass1!" }),
        )
        .await;
    assert_eq!(resp.status, 302, "login: {}", resp.body);
    assert_eq!(resp.location(), "/dashboard");

    // The guest gate now bounces the authenticated user off /login.
    let resp = client.get("/login").await;
    assert_eq!(resp.status, 302, "guest gate must bounce a logged-in user");
    assert_eq!(resp.location(), "/dashboard");

    // The profile page renders for the authenticated user.
    let resp = client.get("/profile").await;
    assert_eq!(resp.status, 200, "GET /profile must render: {}", resp.body);

    // --- PATCH /profile: change name + email. The email change nulls the
    //     verification stamp and re-sends the link to the NEW address.
    let fake = &harness.mail;
    let before = fake.count();
    let resp = client
        .patch_json(
            "/profile",
            json!({
                "name": "Edsger Dijkstra",
                "email": "edsger.new@x.com",
                "display_name": "Edsger Dijkstra",
                "handle": "edsger-dijkstra",
            }),
        )
        .await;
    assert_eq!(resp.status, 302, "profile update: {}", resp.body);
    assert_eq!(resp.location(), "/profile");

    let updated = reload("edsger.new@x.com").await;
    assert_eq!(
        updated.name.as_deref(),
        Some("Edsger Dijkstra"),
        "name saved"
    );
    assert!(
        !updated.is_email_verified(),
        "changing the email must null email_verified_at"
    );
    assert_eq!(
        fake.count(),
        before + 1,
        "email change re-sends a verification link"
    );
    fake.assert_sent_to("edsger.new@x.com");

    // The verified gate kicks back in after the email change.
    let resp = client.get("/dashboard").await;
    assert_eq!(resp.status, 302, "re-unverified user is gated again");
    assert_eq!(resp.location(), "/verify-email");

    // --- PUT /profile/password: wrong current password → 422 pinned to the
    //     field; correct current password → rotated.
    let resp = client
        .put_json(
            "/profile/password",
            json!({
                "current_password": "not-the-password",
                "password": "brandnew1!",
                "password_confirmation": "brandnew1!",
            }),
        )
        .await;
    assert_eq!(resp.status, 422, "wrong current password must 422");
    assert!(
        resp.body.contains("current_password"),
        "the 422 pins the current_password field: {}",
        resp.body
    );

    let resp = client
        .put_json(
            "/profile/password",
            json!({
                "current_password": "oldpass1!",
                "password": "brandnew1!",
                "password_confirmation": "brandnew1!",
            }),
        )
        .await;
    assert_eq!(resp.status, 302, "password rotation: {}", resp.body);
    assert_eq!(resp.location(), "/profile");
    let after = reload("edsger.new@x.com").await;
    assert!(
        after.verify_password("brandnew1!").expect("verify rotated"),
        "the rotated password verifies"
    );
    assert!(
        !after.verify_password("oldpass1!").expect("verify old"),
        "the old password no longer verifies"
    );

    // --- DELETE /profile: wrong password → 422 and the account survives;
    //     correct password → row gone + logged out.
    let resp = client
        .delete_json("/profile", json!({ "password": "wrong" }))
        .await;
    assert_eq!(resp.status, 422, "wrong delete password must 422");
    assert!(
        User::find_by_email("edsger.new@x.com")
            .await
            .expect("lookup")
            .is_some(),
        "a rejected delete must not remove the user"
    );

    let resp = client
        .delete_json("/profile", json!({ "password": "brandnew1!" }))
        .await;
    assert_eq!(resp.status, 302, "confirmed delete: {}", resp.body);
    assert_eq!(resp.location(), "/");
    assert!(
        User::find_by_email("edsger.new@x.com")
            .await
            .expect("lookup")
            .is_none(),
        "a confirmed delete removes the user row"
    );

    // The session is gone with the account: /profile now bounces to /login.
    let resp = client.get("/profile").await;
    assert_eq!(resp.status, 302, "deleted account must be logged out");
    assert_eq!(resp.location(), "/login");
}

// ============================================================================
// 5. Literal-redirect pin: `redirect!("/dashboard")` answers a literal 302
// ============================================================================

#[tokio::test]
async fn login_success_redirects_to_literal_dashboard() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    let mut user = User::create("Pin User", "pin@x.com", "supersecret")
        .await
        .expect("create user");
    mark_verified(&mut user).await;

    let resp = client.get("/login").await;
    assert_eq!(resp.status, 200);

    // The login controller's success arm is `redirect!("/dashboard")` - a
    // string literal with a leading `/`. At framework rev 06b9447f this
    // resolved as a route *name* and 500'd (`Route '/dashboard' not found`);
    // since 95777465 the macro dispatches literal shapes to `Redirect::to`.
    let resp = client
        .post_json(
            "/login",
            json!({ "email": "pin@x.com", "password": "supersecret" }),
        )
        .await;
    assert_eq!(
        resp.status, 302,
        "redirect!(\"/dashboard\") must produce a 302, not a named-route 500: {}",
        resp.body
    );
    assert_eq!(
        resp.location(),
        "/dashboard",
        "the Location header carries the literal path"
    );
}

// ============================================================================
// 6. Inertia form contract: validation failures re-render the page with a
//    flat `errors` prop (the 422 envelope is API-client-only), unsafe-verb
//    success redirects are upgraded to 303, and the shared `auth.user` prop
//    rides authenticated page renders.
// ============================================================================

#[tokio::test]
async fn inertia_submissions_render_errors_and_303_redirects() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    let mut user = User::create("Inertia User", "inertia@x.com", "supersecret")
        .await
        .expect("create user");
    mark_verified(&mut user).await;

    let resp = client.get("/login").await;
    assert_eq!(resp.status, 200);

    // Inertia submission + bad credentials → NOT the 422 envelope (which the
    // Inertia client can only display as a raw-JSON error modal) but a
    // re-render of the login page whose flat `errors` prop carries the
    // field message for `useForm().errors`.
    let resp = client
        .inertia_post_json(
            "/login",
            json!({ "email": "inertia@x.com", "password": "wrong" }),
        )
        .await;
    assert_eq!(
        resp.status, 200,
        "an Inertia validation failure re-renders the page: {}",
        resp.body
    );
    let page: Value = serde_json::from_str(&resp.body).expect("an Inertia page object");
    assert_eq!(page["component"], "auth/Login", "page: {}", resp.body);
    assert_eq!(
        page["props"]["errors"]["email"][0], "These credentials do not match our records.",
        "flat field->messages errors prop: {}",
        resp.body
    );

    // The same submission without the X-Inertia flag keeps the API envelope.
    let resp = client
        .post_json(
            "/login",
            json!({ "email": "inertia@x.com", "password": "wrong" }),
        )
        .await;
    assert_eq!(
        resp.status, 422,
        "non-Inertia clients keep the 422 envelope"
    );

    // A successful Inertia POST keeps the browser-default 302 (the 303
    // upgrade is scoped to the verbs a browser would otherwise replay).
    let resp = client
        .inertia_post_json(
            "/login",
            json!({ "email": "inertia@x.com", "password": "supersecret" }),
        )
        .await;
    assert_eq!(resp.status, 302, "Inertia POST login: {}", resp.body);
    assert_eq!(resp.location(), "/dashboard");

    // The shared `auth.user` prop (AuthShare in bootstrap.rs) rides every
    // page render once authenticated - it is what the layout's user menu
    // and Dashboard nav link key off.
    let resp = client.get("/dashboard").await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.body.contains("inertia@x.com"),
        "the shared auth.user prop must ride the dashboard render: {}",
        resp.body
    );

    // An Inertia PUT that redirects is upgraded 302 → 303 so the browser
    // follows with GET instead of replaying the PUT against the target
    // (which loops until the 20-redirect cap without the middleware).
    let resp = client
        .inertia_put_json(
            "/profile/password",
            json!({
                "current_password": "supersecret",
                "password": "evenmoresecret1!",
                "password_confirmation": "evenmoresecret1!",
            }),
        )
        .await;
    assert_eq!(
        resp.status, 303,
        "Inertia PUT redirects must be 303: {}",
        resp.body
    );
    assert_eq!(resp.location(), "/profile");

    // And a failing Inertia PUT re-renders the Profile page with the field
    // error - wrong current password pins `current_password`.
    let resp = client
        .inertia_put_json(
            "/profile/password",
            json!({
                "current_password": "not-the-password",
                "password": "anothernew1!",
                "password_confirmation": "anothernew1!",
            }),
        )
        .await;
    assert_eq!(
        resp.status, 200,
        "Inertia failure re-renders: {}",
        resp.body
    );
    let page: Value = serde_json::from_str(&resp.body).expect("an Inertia page object");
    assert_eq!(page["component"], "Profile", "page: {}", resp.body);
    assert_eq!(
        page["props"]["errors"]["current_password"][0], "The current password is incorrect.",
        "errors prop pins the field: {}",
        resp.body
    );
}

// ============================================================================
// 7. Static files: public root files and built frontend assets resolve
// ============================================================================

/// Pulsar serves `public/` through Suprnova's native fallback static handler.
/// This drives root branding files and hashed frontend build output through
/// the real router + global middleware stack, exactly as a browser requests
/// them.
#[tokio::test]
async fn public_statics_resolve_through_fallback() {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let mut client = Client::new(addr);

    let icon = client.get("/favicon.ico").await;
    assert_eq!(
        icon.status, 200,
        "GET /favicon.ico must serve: {}",
        icon.body
    );
    assert_eq!(
        icon.headers.get("content-type").map(String::as_str),
        Some("image/x-icon")
    );
    assert!(!icon.body.is_empty(), "favicon body must not be empty");
    let icon_len: usize = icon
        .headers
        .get("content-length")
        .expect("favicon response carries Content-Length")
        .parse()
        .expect("favicon Content-Length parses as usize");
    assert!(icon_len > 0, "favicon Content-Length must be non-zero");

    let png = client.get("/favicon-32x32.png").await;
    assert_eq!(png.status, 200, "GET /favicon-32x32.png must serve");
    assert_eq!(
        png.headers.get("content-type").map(String::as_str),
        Some("image/png")
    );
    assert_eq!(
        png.headers.get("cache-control").map(String::as_str),
        Some("public, max-age=86400"),
        "statics carry a day-long cache"
    );
    let png_len: usize = png
        .headers
        .get("content-length")
        .expect("png response carries Content-Length")
        .parse()
        .expect("png Content-Length parses as usize");
    assert!(png_len > 0, "png Content-Length must be non-zero");

    let manifest = client.get("/site.webmanifest").await;
    assert_eq!(manifest.status, 200, "GET /site.webmanifest must serve");
    let manifest_type = manifest
        .headers
        .get("content-type")
        .expect("manifest response carries Content-Type");
    assert!(
        manifest_type.starts_with("application/manifest+json"),
        "manifest content type should be application/manifest+json, got {manifest_type}"
    );
    assert!(
        manifest.body.contains("\"name\": \"Pulsar\""),
        "manifest names the app: {}",
        manifest.body
    );

    if let Ok(build_manifest) = std::fs::read_to_string("public/assets/.vite/manifest.json") {
        let manifest: Value =
            serde_json::from_str(&build_manifest).expect("Vite build manifest parses");
        let entry_asset = manifest["src/main.ts"]["file"]
            .as_str()
            .expect("Vite manifest contains src/main.ts file");
        let asset_path = format!("/assets/{entry_asset}");
        let asset = client.get(&asset_path).await;
        assert_eq!(
            asset.status, 200,
            "GET {asset_path} must serve a built frontend asset: {}",
            asset.body
        );
        assert_eq!(
            asset.headers.get("cache-control").map(String::as_str),
            Some("public, max-age=86400"),
            "built frontend assets carry the static cache policy"
        );
        assert!(
            !asset.body.is_empty(),
            "built frontend asset body must not be empty"
        );
    }

    // A missing public path stays a 404.
    let stray = client.get("/site.webmanifest.bak").await;
    assert_eq!(stray.status, 404);
}
