//! Shared server state.

use sqlx::postgres::PgPool;

use crate::auth::Sessions;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub sessions: Sessions,
}
