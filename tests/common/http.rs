//! HTTP harness shared by browser-like integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sea_orm_migration::MigratorTrait;
use serde_json::Value;

use suprnova::auth::AuthConfig;
use suprnova::mail::{Mail, MailFake};
use suprnova::{
    App, Auth, AuthManager, CsrfMiddleware, EloquentUserProvider, IncludeMiddleware,
    Inertia303Middleware, MiddlewareRegistry, SessionConfig, SessionMiddleware, handle_request,
};

use pulsar::middleware::LoggingMiddleware;
use pulsar::migrations::Migrator;
use pulsar::models::user::User;

/// Held-for-the-test guard: keeps global container bindings installed and
/// aborts the spawned loopback server on drop.
pub struct Harness {
    _lock: tokio::sync::MutexGuard<'static, ()>,
    pub mail: MailFake,
    server: Option<tokio::task::AbortHandle>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

/// Fresh in-memory DB plus the same app bindings used by HTTP flow tests.
pub async fn setup() -> Harness {
    let lock = super::TEST_LOCK.lock().await;

    // SAFETY: every caller holds `TEST_LOCK` for the harness lifetime.
    unsafe {
        std::env::set_var("MAIL_FROM", "test@pulsar.test");
        std::env::set_var("APP_URL", "http://pulsar.test");
    }
    let mail = Mail::fake();

    suprnova::Crypt::init(suprnova::EncryptionKey::generate());

    let conn = sea_orm::Database::connect("sqlite::memory:")
        .await
        .expect("connect sqlite::memory:");
    Migrator::up(&conn, None)
        .await
        .expect("run Pulsar migrations against sqlite::memory:");
    App::singleton(suprnova::DbConnection::from_raw(conn));
    let db = suprnova::DB::connection().expect("DB not initialized");
    let magnetar = suprnova::MagnetarConfig::from_sea_orm(db.inner().clone()).passkey_config(
        suprnova::PasskeyConfig {
            rp_id: std::env::var("PASSKEY_RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_origin: std::env::var("PASSKEY_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost".to_string()),
        },
    );
    suprnova::init_magnetar(magnetar)
        .await
        .expect("Failed to initialize Magnetar");
    suprnova::rate_limit::bootstrap_default().await;

    App::singleton(AuthManager::new(AuthConfig::default()));
    Auth::register_provider("users", Arc::new(EloquentUserProvider::<User>::new()))
        .expect("register users provider");

    // The throttle middleware drives the `RateLimiter` facade, which resolves
    // a `CacheStore` from the container for its attempt counters. Tests
    // serialize on `TEST_LOCK` but the cache store is process-global, so bind a
    // fresh in-memory cache per test to keep attempt counters isolated across
    // cases.
    App::bind::<dyn suprnova::CacheStore>(Arc::new(suprnova::InMemoryCache::new()));

    App::register_inertia_shared(Arc::new(pulsar::bootstrap::AuthShare));

    Harness {
        _lock: lock,
        mail,
        server: None,
    }
}

impl Harness {
    /// Spawn the real Pulsar router behind the same middleware stack used in
    /// the app, listening on an ephemeral loopback address.
    pub async fn spawn_app(&mut self) -> SocketAddr {
        let router = Arc::new(pulsar::routes::register());
        let registry = Arc::new(
            MiddlewareRegistry::new()
                .append(LoggingMiddleware)
                .append(SessionMiddleware::new(SessionConfig::from_env()))
                .append(CsrfMiddleware::new())
                .append(IncludeMiddleware)
                .append(Inertia303Middleware::new()),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("local_addr");

        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                let router = router.clone();
                let registry = registry.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<Incoming>| {
                        let router = router.clone();
                        let registry = registry.clone();
                        async move { Ok::<_, Infallible>(handle_request(router, registry, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        self.server = Some(accept_loop.abort_handle());

        addr
    }
}

/// Create a configured harness and browser-like client.
pub async fn spawned_client() -> (Harness, Client) {
    let mut harness = setup().await;
    let addr = harness.spawn_app().await;
    let client = Client::new(addr);
    (harness, client)
}

/// One captured HTTP exchange.
pub struct Resp {
    /// HTTP status code.
    pub status: u16,
    /// Lowercased header names, last value wins.
    pub headers: HashMap<String, String>,
    /// Response body as lossy UTF-8 text.
    pub body: String,
}

impl Resp {
    /// Return the `Location` header or panic with a useful message.
    pub fn location(&self) -> &str {
        self.headers
            .get("location")
            .map(String::as_str)
            .unwrap_or_else(|| panic!("expected a Location header, got: {:?}", self.headers))
    }
}

/// A minimal browser: cookie jar plus CSRF echo for state-changing verbs.
pub struct Client {
    addr: SocketAddr,
    cookies: HashMap<String, String>,
}

impl Client {
    /// Create a client for the spawned loopback app.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            cookies: HashMap::new(),
        }
    }

    /// Send a GET request.
    pub async fn get(&mut self, path: &str) -> Resp {
        self.request("GET", path, None, false).await
    }

    /// Send a JSON POST request.
    pub async fn post_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("POST", path, Some(body), false).await
    }

    /// Send an Inertia-flagged JSON POST request.
    pub async fn inertia_post_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("POST", path, Some(body), true).await
    }

    /// Send a JSON PATCH request.
    pub async fn patch_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("PATCH", path, Some(body), false).await
    }

    /// Send a JSON PUT request.
    pub async fn put_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("PUT", path, Some(body), false).await
    }

    /// Send an Inertia-flagged JSON PUT request.
    pub async fn inertia_put_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("PUT", path, Some(body), true).await
    }

    /// Send a JSON DELETE request.
    pub async fn delete_json(&mut self, path: &str, body: Value) -> Resp {
        self.request("DELETE", path, Some(body), false).await
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        inertia: bool,
    ) -> Resp {
        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect to test server");
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io)
            .await
            .expect("client handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let payload = body.map(|v| Bytes::from(v.to_string())).unwrap_or_default();

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "pulsar.test")
            .header("Content-Length", payload.len().to_string());
        if !payload.is_empty() {
            builder = builder.header("Content-Type", "application/json");
        }
        if inertia {
            builder = builder.header("X-Inertia", "true");
        }
        if !self.cookies.is_empty() {
            let jar = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header("Cookie", jar);
        }
        if matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
            && let Some(token) = self.cookies.get("XSRF-TOKEN")
        {
            builder = builder.header("X-XSRF-TOKEN", token.as_str());
        }

        let req = builder.body(Full::new(payload)).expect("build request");
        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
            .await
            .expect("send_request timeout")
            .expect("hyper send_request");

        let (parts, body) = resp.into_parts();
        for value in parts.headers.get_all("set-cookie") {
            let Ok(raw) = value.to_str() else { continue };
            let mut segments = raw.split(';');
            let Some((name, val)) = segments.next().and_then(|nv| nv.split_once('=')) else {
                continue;
            };
            let expired = segments.any(|attr| {
                let attr = attr.trim().to_ascii_lowercase();
                attr == "max-age=0"
            });
            if expired || val.is_empty() {
                self.cookies.remove(name.trim());
            } else {
                self.cookies
                    .insert(name.trim().to_string(), val.to_string());
            }
        }

        let headers = parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let bytes = body.collect().await.expect("collect body").to_bytes();
        Resp {
            status: parts.status.as_u16(),
            headers,
            body: String::from_utf8_lossy(&bytes).to_string(),
        }
    }
}
