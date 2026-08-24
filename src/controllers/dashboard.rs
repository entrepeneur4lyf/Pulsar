//! Dashboard controller.
//!
//! Renders the post-login landing page with the currently authenticated
//! user's basic profile data.

use serde::Serialize;
use suprnova::{
    Auth, FrameworkError, InertiaProps, MustVerifyEmail, Request, Response, handler,
    inertia_response,
};

use crate::controllers::inertia_config;
use crate::models::user::User;

#[derive(Serialize)]
pub struct UserInfo {
    pub id: i64,
    pub name: String,
    pub email: String,
}

#[derive(InertiaProps)]
pub struct DashboardProps {
    pub user: UserInfo,
    pub cards: Vec<DashboardCard>,
    pub actions: Vec<DashboardAction>,
    pub account: AccountStatus,
}

#[derive(Serialize)]
pub struct DashboardCard {
    pub title: String,
    pub value: String,
    pub helper: String,
    pub icon: String,
}

#[derive(Serialize)]
pub struct DashboardAction {
    pub title: String,
    pub body: String,
    pub href: String,
    pub icon: String,
}

#[derive(Serialize)]
pub struct AccountStatus {
    pub email_verified: bool,
}

#[handler]
pub async fn index(req: Request) -> Response {
    // The registered user provider resolves the typed `User` from the
    // session id; `user_as` downcasts the `Authenticatable` for us.
    let user = Auth::user_as::<User>()
        .await?
        .ok_or(FrameworkError::Unauthorized)?;
    let email_verified = user.is_email_verified();

    inertia_response!(
        &req,
        "Dashboard",
        DashboardProps {
            user: UserInfo {
                id: user.id,
                name: user.name.unwrap_or_else(|| "Account".to_owned()),
                email: user.email,
            },
            account: AccountStatus { email_verified },
            cards: vec![
                DashboardCard {
                    title: "Starter kit".to_string(),
                    value: "Ready".to_string(),
                    helper: "Landing, auth, profile, and static assets are wired.".to_string(),
                    icon: "mdi-rocket-launch-outline".to_string(),
                },
                DashboardCard {
                    title: "Auth flows".to_string(),
                    value: "Verified".to_string(),
                    helper: "Email verification, password reset, and profile updates are active."
                        .to_string(),
                    icon: "mdi-shield-check-outline".to_string(),
                },
                DashboardCard {
                    title: "Content engine".to_string(),
                    value: "Planned".to_string(),
                    helper: "Docs and articles are next in the kit roadmap.".to_string(),
                    icon: "mdi-file-document-edit-outline".to_string(),
                },
            ],
            actions: vec![
                DashboardAction {
                    title: "Manage profile".to_string(),
                    body: "Update your account details, password, and verification status."
                        .to_string(),
                    href: "/profile".to_string(),
                    icon: "mdi-account-cog-outline".to_string(),
                },
                DashboardAction {
                    title: "Review landing page".to_string(),
                    body: "Check the public kit homepage and starter-kit messaging.".to_string(),
                    href: "/".to_string(),
                    icon: "mdi-home-search-outline".to_string(),
                },
            ],
        },
        inertia_config()
    )
}
