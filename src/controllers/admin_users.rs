//! Admin user management surface.

use serde::Serialize;
use suprnova::eloquent::Model;
use suprnova::{HasRoles, InertiaProps, Request, Response, handler, inertia_response};

use crate::controllers::inertia_config;
use crate::models::user::User;

const ROLES: [&str; 5] = ["admin", "moderator", "author", "contributor", "member"];

#[derive(Serialize)]
pub struct AdminUserRow {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub verified: bool,
    pub roles: Vec<String>,
    pub created_at: String,
}

#[derive(InertiaProps)]
pub struct AdminUsersIndexProps {
    pub users: Vec<AdminUserRow>,
}

#[handler]
pub async fn index(req: Request) -> Response {
    let users = User::query().order_by_asc("id").get().await?;

    let mut rows = Vec::with_capacity(users.len());
    for user in users.iter() {
        let mut roles = Vec::new();
        for role in ROLES {
            if user.has_role(role).await? {
                roles.push(role.to_string());
            }
        }

        rows.push(AdminUserRow {
            id: user.id,
            name: user.name.clone().unwrap_or_else(|| "Account".to_owned()),
            email: user.email.clone(),
            verified: user.email_verified_at.is_some(),
            roles,
            created_at: user.created_at.to_rfc3339(),
        });
    }

    inertia_response!(
        &req,
        "admin/users/Index",
        AdminUsersIndexProps { users: rows },
        inertia_config()
    )
}
