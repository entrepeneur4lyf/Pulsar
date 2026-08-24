//! V2 foundation flow tests.

mod common;

mod v2_foundation_flows {
    use chrono::Utc;
    use serde_json::json;

    use suprnova::attrs;
    use suprnova::eloquent::Model;
    use suprnova::mail::Mail;
    use suprnova::sea_orm::{DatabaseBackend, Statement};
    use suprnova::{ConnectionTrait, DB, HasRoles, MustVerifyEmail};

    use super::common::{Client, setup};
    use pulsar::commands::users_promote::seed_default_roles;
    use pulsar::models::badge::Badge;
    use pulsar::models::category::Category;
    use pulsar::models::profile::Profile;
    use pulsar::models::reputation_event::ReputationEvent;
    use pulsar::models::tag::Tag;
    use pulsar::models::topic::Topic;
    use pulsar::models::user::User;

    async fn verified_user(name: &str, email: &str) -> User {
        let mut user = User::create(name, email, "secretpass")
            .await
            .expect("create user");
        user.email_verified_at = Some(Utc::now());
        Model::save(&user).await.expect("verify user");
        user
    }

    async fn login(client: &mut Client, email: &str) {
        let page = client.get("/login").await;
        assert_eq!(page.status, 200, "GET /login should set CSRF cookie");

        let resp = client
            .post_json(
                "/login",
                json!({
                    "email": email,
                    "password": "secretpass",
                    "remember": false,
                }),
            )
            .await;
        assert_eq!(resp.status, 302, "login should redirect: {}", resp.body);
        assert_eq!(resp.location(), "/dashboard");
    }

    async fn verified_admin(name: &str, email: &str) -> User {
        seed_default_roles().await.expect("seed roles");
        let user = verified_user(name, email).await;
        user.assign_role("admin").await.expect("assign admin");
        user
    }

    async fn public_profile(user: &User, handle: &str, display_name: &str) -> Profile {
        let mut profile = Profile::ensure_for_user(user)
            .await
            .expect("ensure profile for public profile");
        profile.handle = handle.to_string();
        profile.display_name = display_name.to_string();
        Model::save(&profile).await.expect("save public profile");
        profile
    }

    #[tokio::test]
    async fn profile_is_created_for_registered_users() {
        let mut harness = setup().await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        let resp = client.get("/register").await;
        assert_eq!(resp.status, 200, "GET /register must render: {}", resp.body);

        let _mail = Mail::fake();
        let resp = client
            .post_json(
                "/register",
                json!({
                    "name": "Katherine Johnson",
                    "email": "katherine@pulsar.test",
                    "password": "supersecret",
                    "password_confirmation": "supersecret",
                }),
            )
            .await;
        assert_eq!(resp.status, 302, "register must redirect: {}", resp.body);
        assert_eq!(resp.location(), "/dashboard");

        let user = User::find_by_email("katherine@pulsar.test")
            .await
            .expect("lookup registered user")
            .expect("registered user exists");
        assert_eq!(user.name.as_deref(), Some("Katherine Johnson"));

        let profile = Profile::find_by_user_id(user.id)
            .await
            .expect("lookup profile by user id")
            .expect("registered user has a profile");
        assert_eq!(profile.user_id, user.id);
        assert_eq!(
            profile.display_name,
            user.name.unwrap_or_else(|| "Account".to_owned())
        );
    }

    #[tokio::test]
    async fn registration_rejects_names_longer_than_profile_display_name() {
        let mut harness = setup().await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        let email = "too-long-name@pulsar.test";
        let long_name = "A".repeat(121);

        let resp = client.get("/register").await;
        assert_eq!(resp.status, 200, "GET /register must render: {}", resp.body);

        let _mail = Mail::fake();
        let resp = client
            .post_json(
                "/register",
                json!({
                    "name": long_name,
                    "email": email,
                    "password": "supersecret",
                    "password_confirmation": "supersecret",
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "too-long name should be rejected before user creation: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Name must be at most 120 characters"),
            "validation response should explain the name limit: {}",
            resp.body
        );
        assert!(
            User::find_by_email(email)
                .await
                .expect("lookup rejected user")
                .is_none(),
            "a rejected registration must not create the user"
        );
    }

    #[tokio::test]
    async fn account_delete_removes_registered_users_profile() {
        let mut harness = setup().await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        let email = "delete-profile@pulsar.test";

        let resp = client.get("/register").await;
        assert_eq!(resp.status, 200, "GET /register must render: {}", resp.body);

        let _mail = Mail::fake();
        let resp = client
            .post_json(
                "/register",
                json!({
                    "name": "Delete Profile",
                    "email": email,
                    "password": "supersecret",
                    "password_confirmation": "supersecret",
                }),
            )
            .await;
        assert_eq!(resp.status, 302, "register must redirect: {}", resp.body);

        let user = User::find_by_email(email)
            .await
            .expect("lookup registered user")
            .expect("registered user exists");
        let user_id = user.id;
        assert!(
            Profile::find_by_user_id(user_id)
                .await
                .expect("lookup created profile")
                .is_some(),
            "registration creates a profile before deletion"
        );

        let resp = client
            .delete_json("/profile", json!({ "password": "supersecret" }))
            .await;
        assert_eq!(resp.status, 302, "delete account redirects: {}", resp.body);
        assert_eq!(resp.location(), "/");
        assert!(
            User::find_by_email(email)
                .await
                .expect("lookup deleted user")
                .is_none(),
            "account deletion removes the user"
        );
        assert!(
            Profile::find_by_user_id(user_id)
                .await
                .expect("lookup deleted user's profile")
                .is_none(),
            "account deletion removes the profile"
        );
    }

    #[tokio::test]
    async fn failed_profile_creation_does_not_leave_registered_user() {
        let mut harness = setup().await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        let email = "profile-failure@pulsar.test";

        // `user_id` is guarded, so this fixture sets it through the trusted
        // unguarded path the same way `ensure_for_user` does.
        suprnova::unguarded(|| {
            <Profile as Model>::create(attrs! {
                user_id: 999_i64,
                handle: "user-1",
                display_name: "Handle Collision",
            })
        })
        .await
        .expect("create profile handle collision");

        let resp = client.get("/register").await;
        assert_eq!(resp.status, 200, "GET /register must render: {}", resp.body);

        let _mail = Mail::fake();
        let resp = client
            .post_json(
                "/register",
                json!({
                    "name": "Profile Failure",
                    "email": email,
                    "password": "supersecret",
                    "password_confirmation": "supersecret",
                }),
            )
            .await;

        assert_ne!(
            resp.status, 302,
            "profile creation failure must not complete registration"
        );
        assert!(
            User::find_by_email(email)
                .await
                .expect("lookup compensated user")
                .is_none(),
            "failed profile creation must remove the just-created user"
        );
    }

    #[tokio::test]
    async fn profile_find_by_slug_uses_handle() {
        let _harness = setup().await;
        let user = User::create("Slug User", "profile-slug@pulsar.test", "supersecret")
            .await
            .expect("create user");
        let profile = Profile::ensure_for_user(&user)
            .await
            .expect("ensure profile");

        let found = Profile::find_by_slug(&profile.handle)
            .await
            .expect("lookup profile by slug")
            .expect("profile slug resolves by handle");

        assert_eq!(found.id, profile.id);
    }

    #[tokio::test]
    async fn profile_update_requires_handle() {
        let mut harness = setup().await;
        let email = "handle-required@pulsar.test";
        let user = verified_user("Handle Required", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Handle Required",
                    "email": email,
                    "display_name": "Handle Required",
                    "handle": "",
                }),
            )
            .await;

        assert_eq!(resp.status, 422, "blank handle should be rejected");
        assert!(
            resp.body.contains("Handle is required."),
            "validation response should mention required handle: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_requires_slug_safe_handle() {
        let mut harness = setup().await;
        let email = "handle-slug@pulsar.test";
        let user = verified_user("Handle Slug", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Handle Slug",
                    "email": email,
                    "display_name": "Handle Slug",
                    "handle": "Bad Handle!",
                }),
            )
            .await;

        assert_eq!(resp.status, 422, "slug-unsafe handle should be rejected");
        assert!(
            resp.body
                .contains("Handle may only contain lowercase letters, numbers, and hyphens."),
            "validation response should explain slug-safe handles: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_requires_unique_handle() {
        let mut harness = setup().await;
        let existing = verified_user("Existing Handle", "existing-handle@pulsar.test").await;
        public_profile(&existing, "taken-handle", "Existing Handle").await;

        let email = "new-handle-owner@pulsar.test";
        let user = verified_user("New Handle Owner", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "New Handle Owner",
                    "email": email,
                    "display_name": "New Handle Owner",
                    "handle": "taken-handle",
                }),
            )
            .await;

        assert_eq!(resp.status, 422, "duplicate handle should be rejected");
        assert!(
            resp.body.contains("This handle is already taken."),
            "validation response should explain handle uniqueness: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_rejects_unsafe_public_urls() {
        let mut harness = setup().await;
        let email = "unsafe-urls@pulsar.test";
        let user = verified_user("Unsafe URLs", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Unsafe URLs",
                    "email": email,
                    "display_name": "Unsafe URLs",
                    "handle": "unsafe-urls",
                    "website_url": "javascript:alert(1)",
                    "github_url": "data:text/html,<h1>x</h1>",
                }),
            )
            .await;

        assert_eq!(resp.status, 422, "unsafe public URLs should be rejected");
        assert!(
            resp.body
                .contains("Website URL must start with http:// or https://.")
                && resp
                    .body
                    .contains("GitHub URL must start with http:// or https://."),
            "validation response should explain public URL requirements: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_rejects_reserved_generated_handles() {
        let mut harness = setup().await;
        let email = "reserved-handle@pulsar.test";
        let user = verified_user("Reserved Handle", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Reserved Handle",
                    "email": email,
                    "display_name": "Reserved Handle",
                    "handle": "user-123",
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "reserved generated handle should be rejected"
        );
        assert!(
            resp.body
                .contains("Handles matching user-{number} are reserved."),
            "validation response should explain reserved handles: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_allows_owner_to_keep_default_generated_handle() {
        let mut harness = setup().await;
        let email = "default-handle@pulsar.test";
        let user = verified_user("Default Handle", email).await;
        let profile = Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        assert_eq!(profile.handle, format!("user-{}", user.id));
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Default Handle",
                    "email": email,
                    "display_name": "Default Handle",
                    "handle": profile.handle,
                    "bio": "Updated while keeping the generated handle.",
                }),
            )
            .await;

        assert_eq!(
            resp.status, 302,
            "owner should be able to keep their generated handle: {}",
            resp.body
        );
        assert_eq!(resp.location(), "/profile");

        let updated = Profile::find_by_user_id(user.id)
            .await
            .expect("reload profile")
            .expect("profile exists");
        assert_eq!(updated.handle, format!("user-{}", user.id));
        assert_eq!(
            updated.bio.as_deref(),
            Some("Updated while keeping the generated handle.")
        );
    }

    #[tokio::test]
    async fn profile_update_rolls_back_user_when_profile_save_fails() {
        let mut harness = setup().await;
        let email = "atomic-profile@pulsar.test";
        let user = verified_user("Atomic Original", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");

        let db = DB::connection().expect("resolve test database connection");
        db.inner()
            .execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "CREATE TRIGGER fail_profile_update \
                 BEFORE UPDATE ON profiles \
                 BEGIN SELECT RAISE(ABORT, 'forced profile update failure'); END;"
                    .to_string(),
            ))
            .await
            .expect("install failing profile update trigger");

        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Atomic Changed",
                    "email": "atomic-profile-new@pulsar.test",
                    "display_name": "Atomic Changed",
                    "handle": "atomic-profile",
                    "bio": "This profile save is forced to fail.",
                }),
            )
            .await;

        assert_ne!(
            resp.status, 302,
            "profile failure should not report a successful update"
        );
        assert!(
            User::find_by_email("atomic-profile-new@pulsar.test")
                .await
                .expect("lookup new email")
                .is_none(),
            "failed profile save must not leave the user under the new email"
        );
        let reloaded = User::find_by_email(email)
            .await
            .expect("lookup original email")
            .expect("original user row should remain");
        assert_eq!(reloaded.name.as_deref(), Some("Atomic Original"));
        assert_eq!(reloaded.email, email);
        assert!(
            reloaded.is_email_verified(),
            "failed profile save must not clear email verification"
        );
    }

    #[tokio::test]
    async fn profile_update_rejects_whitespace_required_values() {
        let mut harness = setup().await;
        let email = "whitespace-profile@pulsar.test";
        let user = verified_user("Whitespace Profile", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "   ",
                    "email": email,
                    "display_name": "   ",
                    "handle": "   ",
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "whitespace required values should be rejected"
        );
        assert!(
            resp.body.contains("Name is required.")
                && resp.body.contains("Display name is required.")
                && resp.body.contains("Handle is required."),
            "validation response should mention all whitespace-only fields: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn profile_update_enforces_database_backed_lengths() {
        let mut harness = setup().await;
        let email = "length-profile@pulsar.test";
        let user = verified_user("Length Profile", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let long_url = format!("https://example.com/{}", "a".repeat(481));
        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "N".repeat(121),
                    "email": email,
                    "display_name": "D".repeat(121),
                    "handle": "h".repeat(65),
                    "avatar_url": long_url,
                    "website_url": format!("https://example.com/{}", "w".repeat(481)),
                    "github_url": format!("https://github.com/{}", "g".repeat(482)),
                    "location": "L".repeat(121),
                    "timezone": "T".repeat(81),
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "overlong profile fields should be rejected"
        );
        for expected in [
            "Name must be at most 120 characters.",
            "Display name must be at most 120 characters.",
            "Handle must be at most 64 characters.",
            "Avatar URL must be at most 500 characters.",
            "Website URL must be at most 500 characters.",
            "GitHub URL must be at most 500 characters.",
            "Location must be at most 120 characters.",
            "Timezone must be at most 80 characters.",
        ] {
            assert!(
                resp.body.contains(expected),
                "validation response should contain `{expected}`: {}",
                resp.body
            );
        }
    }

    #[tokio::test]
    async fn profile_update_saves_public_member_fields() {
        let mut harness = setup().await;
        let email = "profile-fields@pulsar.test";
        let user = verified_user("Profile Fields", email).await;
        Profile::ensure_for_user(&user)
            .await
            .expect("ensure current profile");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, email).await;

        let resp = client
            .patch_json(
                "/profile",
                json!({
                    "name": "Grace Account",
                    "email": email,
                    "display_name": "Grace Hopper",
                    "handle": "grace-hopper",
                    "bio": "Compiler pioneer and naval officer.",
                    "avatar_url": "https://cdn.pulsar.test/grace.png",
                    "website_url": "https://grace.example",
                    "github_url": "https://github.com/grace",
                    "location": "Arlington, VA",
                    "timezone": "America/New_York",
                }),
            )
            .await;

        assert_eq!(resp.status, 302, "profile field update: {}", resp.body);
        assert_eq!(resp.location(), "/profile");

        let updated = User::find_by_email(email)
            .await
            .expect("reload user")
            .expect("updated user exists");
        assert_eq!(updated.name.as_deref(), Some("Grace Account"));

        let profile = Profile::find_by_user_id(updated.id)
            .await
            .expect("reload profile")
            .expect("profile exists");
        assert_eq!(profile.handle, "grace-hopper");
        assert_eq!(profile.display_name, "Grace Hopper");
        assert_eq!(
            profile.bio.as_deref(),
            Some("Compiler pioneer and naval officer.")
        );
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://cdn.pulsar.test/grace.png")
        );
        assert_eq!(
            profile.website_url.as_deref(),
            Some("https://grace.example")
        );
        assert_eq!(
            profile.github_url.as_deref(),
            Some("https://github.com/grace")
        );
        assert_eq!(profile.location.as_deref(), Some("Arlington, VA"));
        assert_eq!(profile.timezone.as_deref(), Some("America/New_York"));

        let resp = client.get("/members/grace-hopper").await;
        assert_eq!(
            resp.status, 200,
            "member profile should render: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Grace Hopper"),
            "public member page should include display name: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn members_index_lists_public_profiles() {
        let mut harness = setup().await;
        let ada = verified_user("Ada Account", "ada-members@pulsar.test").await;
        public_profile(&ada, "ada-lovelace", "Ada Lovelace").await;
        let alan = verified_user("Alan Account", "alan-members@pulsar.test").await;
        public_profile(&alan, "alan-turing", "Alan Turing").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        let resp = client.get("/members").await;

        assert_eq!(
            resp.status, 200,
            "members index should render: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Ada Lovelace") && resp.body.contains("Alan Turing"),
            "members index should include public profiles: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn member_profile_is_visible_by_handle() {
        let mut harness = setup().await;
        let user = verified_user("Visible Account", "visible-member@pulsar.test").await;
        let mut profile = public_profile(&user, "visible-member", "Visible Member").await;
        profile.bio = Some("Visible public biography.".to_string());
        profile.website_url = Some("https://visible.example".to_string());
        Model::save(&profile)
            .await
            .expect("save visible public profile fields");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        let resp = client.get("/members/visible-member").await;

        assert_eq!(
            resp.status, 200,
            "member profile should render: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Visible Member")
                && resp.body.contains("Visible public biography.")
                && resp.body.contains("visible.example")
                && resp.body.contains("contribution_counts")
                && resp.body.contains("badges"),
            "member profile should expose summary props: {}",
            resp.body
        );

        let missing = client.get("/members/not-a-member").await;
        assert_eq!(missing.status, 404, "unknown handles should 404");
    }

    #[tokio::test]
    async fn badge_find_by_slug_uses_key() {
        let _harness = setup().await;
        let badge = <Badge as Model>::create(attrs! {
            key: "founding-member",
            name: "Founding Member",
            role_scoped: false,
        })
        .await
        .expect("create badge");

        let found = Badge::find_by_slug("founding-member")
            .await
            .expect("lookup badge by slug")
            .expect("badge slug resolves by key");

        assert_eq!(found.id, badge.id);
    }

    #[tokio::test]
    async fn taxonomy_models_find_by_slug() {
        let _harness = setup().await;
        let category = <Category as Model>::create(attrs! {
            name: "Programming",
            slug: "programming",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create category");
        let topic = <Topic as Model>::create(attrs! {
            name: "Rust",
            slug: "rust",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create topic");
        let tag = <Tag as Model>::create(attrs! {
            name: "Async",
            slug: "async",
        })
        .await
        .expect("create tag");

        assert_eq!(
            Category::find_by_slug("programming")
                .await
                .expect("lookup category")
                .expect("category exists")
                .id,
            category.id
        );
        assert_eq!(
            Topic::find_by_slug("rust")
                .await
                .expect("lookup topic")
                .expect("topic exists")
                .id,
            topic.id
        );
        assert_eq!(
            Tag::find_by_slug("async")
                .await
                .expect("lookup tag")
                .expect("tag exists")
                .id,
            tag.id
        );
    }

    #[tokio::test]
    async fn reputation_events_can_be_loaded_for_user_newest_first() {
        let _harness = setup().await;
        let user = User::create("Reputation User", "reputation@pulsar.test", "supersecret")
            .await
            .expect("create user");
        let other = User::create("Other User", "other-reputation@pulsar.test", "supersecret")
            .await
            .expect("create other user");

        // `user_id` is guarded, so these fixtures set it through the trusted
        // unguarded path (the real write paths do likewise).
        let first = suprnova::unguarded(|| {
            <ReputationEvent as Model>::create(attrs! {
                user_id: user.id,
                event_type: "article_published",
                target_type: "Article",
                target_id: 10_i64,
                weight: 5,
            })
        })
        .await
        .expect("create first event");
        let second = suprnova::unguarded(|| {
            <ReputationEvent as Model>::create(attrs! {
                user_id: user.id,
                event_type: "comment_featured",
                target_type: "Comment",
                target_id: 20_i64,
                weight: 3,
            })
        })
        .await
        .expect("create second event");
        suprnova::unguarded(|| {
            <ReputationEvent as Model>::create(attrs! {
                user_id: other.id,
                event_type: "other_user_event",
                target_type: "Article",
                target_id: 30_i64,
                weight: 1,
            })
        })
        .await
        .expect("create other user event");

        let events = ReputationEvent::for_user(user.id)
            .await
            .expect("load reputation events");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, second.id);
        assert_eq!(events[1].id, first.id);
    }

    #[tokio::test]
    async fn member_cannot_open_admin_taxonomy() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Taxonomy Member", "taxonomy-member@pulsar.test").await;
        user.assign_role("member").await.expect("assign member");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-member@pulsar.test").await;

        let resp = client.get("/admin/taxonomy").await;
        assert_eq!(resp.status, 403);
    }

    #[tokio::test]
    async fn member_cannot_create_admin_category() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Taxonomy Writer", "taxonomy-writer@pulsar.test").await;
        user.assign_role("member").await.expect("assign member");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-writer@pulsar.test").await;

        let resp = client
            .post_json(
                "/admin/categories",
                json!({
                    "name": "Forbidden Category",
                    "slug": "forbidden-category",
                    "description": "Members cannot manage taxonomy.",
                    "sort_order": 5,
                    "is_visible": true,
                }),
            )
            .await;

        assert_eq!(resp.status, 403);
        assert!(
            Category::find_by_slug("forbidden-category")
                .await
                .expect("lookup forbidden category")
                .is_none(),
            "denied taxonomy writes must not create a category"
        );
    }

    #[tokio::test]
    async fn taxonomy_member_cannot_delete_admin_category() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user(
            "Taxonomy Delete Member",
            "taxonomy-delete-member@pulsar.test",
        )
        .await;
        user.assign_role("member").await.expect("assign member");
        let category = <Category as Model>::create(attrs! {
            name: "Protected Category",
            slug: "protected-category",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create protected category");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-delete-member@pulsar.test").await;

        let resp = client
            .delete_json(&format!("/admin/categories/{}", category.id), json!({}))
            .await;

        assert_eq!(resp.status, 403);
        assert!(
            Category::find_by_slug("protected-category")
                .await
                .expect("lookup protected category")
                .is_some(),
            "denied taxonomy deletes must not remove the category"
        );
    }

    #[tokio::test]
    async fn admin_can_create_taxonomy_category() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Admin", "taxonomy-admin@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-admin@pulsar.test").await;

        let resp = client
            .post_json(
                "/admin/categories",
                json!({
                    "name": "Programming",
                    "slug": "programming",
                    "description": "Languages, tooling, and software practice.",
                    "sort_order": 10,
                    "is_visible": true,
                }),
            )
            .await;

        assert_eq!(
            resp.status, 302,
            "admin category creation should redirect: {}",
            resp.body
        );
        assert_eq!(resp.location(), "/admin/taxonomy");

        let category = Category::find_by_slug("programming")
            .await
            .expect("lookup created category")
            .expect("created category exists");
        assert_eq!(category.name, "Programming");
        assert_eq!(
            category.description.as_deref(),
            Some("Languages, tooling, and software practice.")
        );
        assert_eq!(category.sort_order, 10);
        assert!(category.is_visible);
    }

    #[tokio::test]
    async fn inertia_taxonomy_validation_uses_admin_taxonomy_url() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Inertia Admin", "taxonomy-inertia@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-inertia@pulsar.test").await;

        let resp = client
            .inertia_post_json(
                "/admin/topics",
                json!({
                    "name": "",
                    "slug": "inertia-topic",
                    "description": "Validation should render the admin taxonomy page.",
                    "sort_order": 0,
                    "is_visible": true,
                }),
            )
            .await;

        assert_eq!(
            resp.status, 200,
            "Inertia validation should re-render: {}",
            resp.body
        );
        assert!(
            resp.body.contains("\"url\":\"/admin/taxonomy\"")
                && !resp.body.contains("\"url\":\"/admin/topics\""),
            "Inertia validation must use the GET taxonomy page URL: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Name is required."),
            "validation response should include field errors: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn taxonomy_term_validation_reports_malformed_sort_order() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Sort Admin", "taxonomy-sort@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-sort@pulsar.test").await;

        let resp = client
            .post_json(
                "/admin/categories",
                json!({
                    "name": "Broken Sort",
                    "slug": "broken-sort",
                    "description": "Malformed sort order should be a field error.",
                    "sort_order": "",
                    "is_visible": true,
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "malformed sort_order should return validation errors: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Sort order is required.")
                || resp.body.contains("Sort order must be an integer."),
            "validation response should mention sort_order: {}",
            resp.body
        );
        assert!(
            Category::find_by_slug("broken-sort")
                .await
                .expect("lookup broken sort category")
                .is_none(),
            "invalid sort_order must not create a category"
        );
    }

    #[tokio::test]
    async fn taxonomy_duplicate_slugs_return_validation_errors() {
        let mut harness = setup().await;
        verified_admin(
            "Taxonomy Duplicate Admin",
            "taxonomy-duplicates@pulsar.test",
        )
        .await;
        <Category as Model>::create(attrs! {
            name: "Existing Category",
            slug: "existing-category",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create existing category");
        let first_topic = <Topic as Model>::create(attrs! {
            name: "First Topic",
            slug: "first-topic",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create first topic");
        let second_topic = <Topic as Model>::create(attrs! {
            name: "Second Topic",
            slug: "second-topic",
            sort_order: 1,
            is_visible: true,
        })
        .await
        .expect("create second topic");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-duplicates@pulsar.test").await;

        let create = client
            .post_json(
                "/admin/categories",
                json!({
                    "name": "Duplicate Category",
                    "slug": "existing-category",
                    "description": null,
                    "sort_order": 2,
                    "is_visible": true,
                }),
            )
            .await;
        assert_eq!(
            create.status, 422,
            "duplicate category slug should validate: {}",
            create.body
        );
        assert!(
            create.body.contains("Slug is already in use."),
            "duplicate create should explain slug uniqueness: {}",
            create.body
        );

        let update = client
            .put_json(
                &format!("/admin/topics/{}", second_topic.id),
                json!({
                    "name": "Second Topic",
                    "slug": first_topic.slug,
                    "description": null,
                    "sort_order": 1,
                    "is_visible": true,
                }),
            )
            .await;
        assert_eq!(
            update.status, 422,
            "duplicate topic slug update should validate: {}",
            update.body
        );
        assert!(
            update.body.contains("Slug is already in use."),
            "duplicate update should explain slug uniqueness: {}",
            update.body
        );
    }

    #[tokio::test]
    async fn taxonomy_db_unique_slug_failures_return_validation_errors() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Race Admin", "taxonomy-race@pulsar.test").await;
        let db = DB::connection().expect("resolve test database connection");
        db.inner()
            .execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "CREATE TRIGGER fail_category_slug_unique \
                 BEFORE INSERT ON categories \
                 WHEN NEW.slug = 'race-category' \
                 BEGIN SELECT RAISE(ABORT, 'UNIQUE constraint failed: categories.slug'); END;"
                    .to_string(),
            ))
            .await
            .expect("install unique failure trigger");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-race@pulsar.test").await;

        let resp = client
            .post_json(
                "/admin/categories",
                json!({
                    "name": "Race Category",
                    "slug": "race-category",
                    "description": "Simulates a uniqueness race at write time.",
                    "sort_order": 0,
                    "is_visible": true,
                }),
            )
            .await;

        assert_eq!(
            resp.status, 422,
            "DB unique failures should become validation errors: {}",
            resp.body
        );
        assert!(
            resp.body.contains("Slug is already in use."),
            "DB unique failure should be mapped to slug field error: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn admin_can_create_taxonomy_topics_and_tags() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Create Admin", "taxonomy-create@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-create@pulsar.test").await;

        let topic_resp = client
            .post_json(
                "/admin/topics",
                json!({
                    "name": "Distributed Systems",
                    "slug": "distributed-systems",
                    "description": "Consensus, reliability, and operations.",
                    "sort_order": 8,
                    "is_visible": false,
                }),
            )
            .await;
        assert_eq!(
            topic_resp.status, 302,
            "topic creation should redirect: {}",
            topic_resp.body
        );
        assert_eq!(topic_resp.location(), "/admin/taxonomy");
        let topic = Topic::find_by_slug("distributed-systems")
            .await
            .expect("lookup created topic")
            .expect("created topic exists");
        assert_eq!(topic.name, "Distributed Systems");
        assert_eq!(topic.sort_order, 8);
        assert!(!topic.is_visible);

        let tag_resp = client
            .post_json(
                "/admin/tags",
                json!({
                    "name": "Async",
                    "slug": "async",
                }),
            )
            .await;
        assert_eq!(
            tag_resp.status, 302,
            "tag creation should redirect: {}",
            tag_resp.body
        );
        assert_eq!(tag_resp.location(), "/admin/taxonomy");
        let tag = Tag::find_by_slug("async")
            .await
            .expect("lookup created tag")
            .expect("created tag exists");
        assert_eq!(tag.name, "Async");
    }

    #[tokio::test]
    async fn admin_can_update_category_topic_and_tag() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Update Admin", "taxonomy-update@pulsar.test").await;
        let category = <Category as Model>::create(attrs! {
            name: "Old Category",
            slug: "old-category",
            description: "Old category description.",
            sort_order: 4,
            is_visible: true,
        })
        .await
        .expect("create category");
        let topic = <Topic as Model>::create(attrs! {
            name: "Old Topic",
            slug: "old-topic",
            description: "Old topic description.",
            sort_order: 5,
            is_visible: false,
        })
        .await
        .expect("create topic");
        let tag = <Tag as Model>::create(attrs! {
            name: "Old Tag",
            slug: "old-tag",
        })
        .await
        .expect("create tag");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-update@pulsar.test").await;

        let category_resp = client
            .put_json(
                &format!("/admin/categories/{}", category.id),
                json!({
                    "name": "New Category",
                    "slug": "new-category",
                    "description": "New category description.",
                    "sort_order": 14,
                    "is_visible": false,
                }),
            )
            .await;
        assert_eq!(
            category_resp.status, 302,
            "category update should redirect: {}",
            category_resp.body
        );

        let topic_resp = client
            .put_json(
                &format!("/admin/topics/{}", topic.id),
                json!({
                    "name": "New Topic",
                    "slug": "new-topic",
                    "description": "New topic description.",
                    "sort_order": 15,
                    "is_visible": true,
                }),
            )
            .await;
        assert_eq!(
            topic_resp.status, 302,
            "topic update should redirect: {}",
            topic_resp.body
        );

        let tag_resp = client
            .put_json(
                &format!("/admin/tags/{}", tag.id),
                json!({
                    "name": "New Tag",
                    "slug": "new-tag",
                }),
            )
            .await;
        assert_eq!(
            tag_resp.status, 302,
            "tag update should redirect: {}",
            tag_resp.body
        );

        let category = Category::find_by_slug("new-category")
            .await
            .expect("lookup updated category")
            .expect("updated category exists");
        assert_eq!(category.name, "New Category");
        assert_eq!(
            category.description.as_deref(),
            Some("New category description.")
        );
        assert_eq!(category.sort_order, 14);
        assert!(!category.is_visible);

        let topic = Topic::find_by_slug("new-topic")
            .await
            .expect("lookup updated topic")
            .expect("updated topic exists");
        assert_eq!(topic.name, "New Topic");
        assert_eq!(topic.description.as_deref(), Some("New topic description."));
        assert_eq!(topic.sort_order, 15);
        assert!(topic.is_visible);

        let tag = Tag::find_by_slug("new-tag")
            .await
            .expect("lookup updated tag")
            .expect("updated tag exists");
        assert_eq!(tag.name, "New Tag");
    }

    #[tokio::test]
    async fn taxonomy_admin_can_delete_category_topic_and_tag() {
        let mut harness = setup().await;
        verified_admin("Taxonomy Delete Admin", "taxonomy-delete@pulsar.test").await;
        let category = <Category as Model>::create(attrs! {
            name: "Delete Category",
            slug: "delete-category",
            description: "Visible category to delete.",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create category");
        let topic = <Topic as Model>::create(attrs! {
            name: "Delete Topic",
            slug: "delete-topic",
            description: "Visible topic to delete.",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create topic");
        let tag = <Tag as Model>::create(attrs! {
            name: "Delete Tag",
            slug: "delete-tag",
        })
        .await
        .expect("create tag");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-delete@pulsar.test").await;

        assert_eq!(client.get("/categories/delete-category").await.status, 200);
        assert_eq!(client.get("/topics/delete-topic").await.status, 200);
        assert_eq!(client.get("/tags/delete-tag").await.status, 200);

        let category_resp = client
            .delete_json(&format!("/admin/categories/{}", category.id), json!({}))
            .await;
        assert_eq!(
            category_resp.status, 302,
            "category delete should redirect: {}",
            category_resp.body
        );
        assert_eq!(category_resp.location(), "/admin/taxonomy");

        let topic_resp = client
            .delete_json(&format!("/admin/topics/{}", topic.id), json!({}))
            .await;
        assert_eq!(
            topic_resp.status, 302,
            "topic delete should redirect: {}",
            topic_resp.body
        );
        assert_eq!(topic_resp.location(), "/admin/taxonomy");

        let tag_resp = client
            .delete_json(&format!("/admin/tags/{}", tag.id), json!({}))
            .await;
        assert_eq!(
            tag_resp.status, 302,
            "tag delete should redirect: {}",
            tag_resp.body
        );
        assert_eq!(tag_resp.location(), "/admin/taxonomy");

        assert!(
            Category::find_by_slug("delete-category")
                .await
                .expect("lookup deleted category")
                .is_none(),
            "category delete should remove row"
        );
        assert!(
            Topic::find_by_slug("delete-topic")
                .await
                .expect("lookup deleted topic")
                .is_none(),
            "topic delete should remove row"
        );
        assert!(
            Tag::find_by_slug("delete-tag")
                .await
                .expect("lookup deleted tag")
                .is_none(),
            "tag delete should remove row"
        );

        assert_eq!(
            client.get("/categories/delete-category").await.status,
            404,
            "deleted category detail should no longer render"
        );
        assert_eq!(
            client.get("/topics/delete-topic").await.status,
            404,
            "deleted topic detail should no longer render"
        );
        assert_eq!(
            client.get("/tags/delete-tag").await.status,
            404,
            "deleted tag detail should no longer render"
        );
    }

    #[tokio::test]
    async fn taxonomy_delete_missing_row_returns_not_found() {
        let mut harness = setup().await;
        verified_admin(
            "Taxonomy Missing Delete Admin",
            "taxonomy-missing-delete@pulsar.test",
        )
        .await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "taxonomy-missing-delete@pulsar.test").await;

        let resp = client
            .delete_json("/admin/categories/987654321", json!({}))
            .await;

        assert_eq!(
            resp.status, 404,
            "missing taxonomy delete should return a controlled not found response: {}",
            resp.body
        );
        assert!(
            resp.body.contains("category `987654321`"),
            "missing taxonomy delete should be handled by the taxonomy controller: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn public_topics_show_visible_topics_only() {
        let mut harness = setup().await;
        <Topic as Model>::create(attrs! {
            name: "Rust Programming",
            slug: "rust-programming",
            description: "Ownership, async systems, and practical Rust.",
            sort_order: 1,
            is_visible: true,
        })
        .await
        .expect("create visible topic");
        <Topic as Model>::create(attrs! {
            name: "Private Planning",
            slug: "private-planning",
            description: "Hidden taxonomy work.",
            sort_order: 2,
            is_visible: false,
        })
        .await
        .expect("create hidden topic");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        let index = client.get("/topics").await;
        assert_eq!(
            index.status, 200,
            "topics index should render: {}",
            index.body
        );
        assert!(
            index.body.contains("Rust Programming") && !index.body.contains("Private Planning"),
            "topics index should include visible topics only: {}",
            index.body
        );

        let visible = client.get("/topics/rust-programming").await;
        assert_eq!(
            visible.status, 200,
            "visible topic detail should render: {}",
            visible.body
        );
        assert!(
            visible.body.contains("Rust Programming")
                && visible.body.contains("contribution_counts"),
            "visible topic detail should expose empty contribution counts: {}",
            visible.body
        );

        let hidden = client.get("/topics/private-planning").await;
        assert_eq!(hidden.status, 404, "hidden topic detail should 404");
    }

    #[tokio::test]
    async fn public_category_and_tag_pages_render() {
        let mut harness = setup().await;
        <Category as Model>::create(attrs! {
            name: "Engineering",
            slug: "engineering",
            description: "Technical practice and systems.",
            sort_order: 0,
            is_visible: true,
        })
        .await
        .expect("create visible category");
        <Category as Model>::create(attrs! {
            name: "Hidden Category",
            slug: "hidden-category",
            description: "Hidden taxonomy category.",
            sort_order: 1,
            is_visible: false,
        })
        .await
        .expect("create hidden category");
        <Tag as Model>::create(attrs! {
            name: "Rust",
            slug: "rust",
        })
        .await
        .expect("create tag");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        let category = client.get("/categories/engineering").await;
        assert_eq!(
            category.status, 200,
            "visible category detail should render: {}",
            category.body
        );
        assert!(
            category.body.contains("Engineering") && category.body.contains("contribution_counts"),
            "category detail should expose empty contribution counts: {}",
            category.body
        );

        let hidden = client.get("/categories/hidden-category").await;
        assert_eq!(hidden.status, 404, "hidden category detail should 404");

        let tag = client.get("/tags/rust").await;
        assert_eq!(tag.status, 200, "tag detail should render: {}", tag.body);
        assert!(
            tag.body.contains("Rust") && tag.body.contains("contribution_counts"),
            "tag detail should expose empty contribution counts: {}",
            tag.body
        );
    }

    #[tokio::test]
    async fn moderator_can_open_moderation_access_surface() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Queue Moderator", "queue-moderator@pulsar.test").await;
        user.assign_role("moderator")
            .await
            .expect("assign moderator");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "queue-moderator@pulsar.test").await;

        let resp = client.get("/moderation").await;
        assert_eq!(
            resp.status, 200,
            "moderator should reach moderation foundation surface: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn admin_can_open_admin_users() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Users Admin", "users-admin@pulsar.test").await;
        user.assign_role("admin").await.expect("assign admin");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "users-admin@pulsar.test").await;

        let resp = client.get("/admin/users").await;
        assert_eq!(
            resp.status, 200,
            "admin should reach users foundation surface: {}",
            resp.body
        );
    }

    // ── Task #12: mass-assignment hardening ────────────────────────────────

    #[tokio::test]
    async fn ownership_columns_cannot_be_mass_assigned() {
        let _harness = setup().await;

        // `user_id` is guarded (removed from `fillable`), so the raw mass
        // assignment path must NOT honor the injected ownership id. This goes
        // through `Profile::create` directly, NOT the trusted `ensure_for_user`
        // wrapper that flips the guard off. The injected `user_id` is silently
        // discarded by the fillable filter, leaving the column unset - which the
        // schema (NOT NULL, no default) rejects, so the create fails rather than
        // ever persisting the attacker-controlled owner.
        let result = <Profile as Model>::create(attrs! {
            user_id: 999_i64,
            handle: "mass-assign-guard",
            display_name: "Mass Assign Guard",
        })
        .await;

        assert!(
            result.is_err(),
            "mass-assigning the guarded user_id must not produce a persisted row: {result:?}"
        );
        assert!(
            Profile::find_by_user_id(999)
                .await
                .expect("lookup injected owner")
                .is_none(),
            "no profile may be owned by the attacker-injected user_id"
        );

        // The trusted constructor sets `user_id` explicitly through
        // `unguarded`, so it DOES persist the real owner.
        let owner = User::create("Guard Owner", "guard-owner@pulsar.test", "secretpass")
            .await
            .expect("create owner");
        let profile = Profile::ensure_for_user(&owner)
            .await
            .expect("ensure_for_user sets user_id via unguarded");
        assert_eq!(
            profile.user_id, owner.id,
            "the trusted unguarded path still sets the real owner id"
        );
    }

    // ── Task #13: brute-force throttle on POST /login ──────────────────────

    #[tokio::test]
    async fn repeated_failed_logins_are_throttled() {
        let mut harness = setup().await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);

        // Prime the CSRF cookie so the throttle (not CSRF) is what gates us.
        let page = client.get("/login").await;
        assert_eq!(page.status, 200, "GET /login should set CSRF cookie");

        // The login throttle allows 20 attempts per minute; the 21st must 429.
        let mut last = 0;
        for _ in 0..21 {
            let resp = client
                .post_json(
                    "/login",
                    json!({
                        "email": "nobody@pulsar.test",
                        "password": "wrong",
                        "remember": false,
                    }),
                )
                .await;
            last = resp.status;
        }

        assert_eq!(
            last, 429,
            "the 21st failed login must be rate limited (got {last})"
        );
    }

    // ── Task #14: admin/users + moderation access + content ─────────────────

    #[tokio::test]
    async fn admin_users_page_renders_for_admin() {
        let mut harness = setup().await;
        verified_admin("Page Admin", "page-admin@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "page-admin@pulsar.test").await;

        let resp = client.get("/admin/users").await;
        assert_eq!(
            resp.status, 200,
            "admin should reach the users page: {}",
            resp.body
        );
        assert!(
            resp.body.contains("page-admin@pulsar.test"),
            "users page should list the admin's email: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn admin_users_page_forbidden_for_plain_user() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Plain Users Viewer", "plain-users@pulsar.test").await;
        user.assign_role("member").await.expect("assign member");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "plain-users@pulsar.test").await;

        let resp = client.get("/admin/users").await;
        assert_eq!(
            resp.status, 403,
            "a plain user must not reach the admin users page: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn moderation_page_renders_for_admin() {
        let mut harness = setup().await;
        verified_admin("Moderation Admin", "moderation-admin@pulsar.test").await;
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "moderation-admin@pulsar.test").await;

        let resp = client.get("/moderation").await;
        assert_eq!(
            resp.status, 200,
            "admin should reach the moderation page: {}",
            resp.body
        );
    }

    #[tokio::test]
    async fn moderation_page_forbidden_for_plain_user() {
        let mut harness = setup().await;
        seed_default_roles().await.expect("seed roles");
        let user = verified_user("Plain Moderation Viewer", "plain-moderation@pulsar.test").await;
        user.assign_role("member").await.expect("assign member");
        let addr = harness.spawn_app().await;
        let mut client = Client::new(addr);
        login(&mut client, "plain-moderation@pulsar.test").await;

        let resp = client.get("/moderation").await;
        assert_eq!(
            resp.status, 403,
            "a plain user must not reach the moderation page: {}",
            resp.body
        );
    }
}
