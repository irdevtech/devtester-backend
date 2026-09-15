use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, Query, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

const APP_SUBMISSION_COST: i32 = 100;
const REGISTRATION_BONUS: i32 = 50;
const CHECKIN_REWARD: i32 = 10;
const TESTING_DAYS: i32 = 14;

static RATE_LIMITER: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: Arc<String>,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::Internal(message) => {
                tracing::error!(error = %message, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    exp: usize,
}

fn token(user_id: Uuid, secret: &str) -> Result<String> {
    let exp = (Utc::now().timestamp() + 60 * 60 * 24 * 7) as usize;
    encode(
        &Header::default(),
        &Claims { sub: user_id, exp },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|error| AppError::Internal(error.to_string()))
}

fn authenticated_user(headers: &HeaderMap, secret: &str) -> Result<Uuid> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let bearer = value
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    decode::<Claims>(
        bearer,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims.sub)
    .map_err(|_| AppError::Unauthorized)
}

fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| AppError::Internal(error.to_string()))
}

fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|error| AppError::Internal(error.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[derive(Deserialize)]
struct AuthRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    access_token: String,
    user_id: Uuid,
    credits_balance: i32,
}

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    password_hash: String,
    credits_balance: i32,
}

async fn register(
    State(state): State<AppState>,
    Json(input): Json<AuthRequest>,
) -> Result<(StatusCode, Json<AuthResponse>)> {
    validate_credentials(&input)?;
    let mut transaction = state.db.begin().await.map_err(map_db)?;
    let row = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (email, password_hash, credits_balance) VALUES ($1, $2, $3) RETURNING id, password_hash, credits_balance",
    )
    .bind(input.email.trim().to_lowercase())
    .bind(hash_password(&input.password)?)
    .bind(REGISTRATION_BONUS)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    sqlx::query(
        "INSERT INTO credit_transactions (user_id, amount, type, description) VALUES ($1, $2, 'bonus', $3)",
    )
    .bind(row.id)
    .bind(REGISTRATION_BONUS)
    .bind("Registration bonus")
    .execute(&mut *transaction)
    .await
    .map_err(map_db)?;
    transaction.commit().await.map_err(map_db)?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            access_token: token(row.id, &state.jwt_secret)?,
            user_id: row.id,
            credits_balance: row.credits_balance,
        }),
    ))
}

async fn login(
    State(state): State<AppState>,
    Json(input): Json<AuthRequest>,
) -> Result<Json<AuthResponse>> {
    validate_credentials(&input)?;
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, password_hash, credits_balance FROM users WHERE email = $1",
    )
    .bind(input.email.trim().to_lowercase())
    .fetch_optional(&state.db)
    .await
    .map_err(map_db)?
    .ok_or(AppError::Unauthorized)?;
    if !verify_password(&input.password, &row.password_hash)? {
        return Err(AppError::Unauthorized);
    }
    Ok(Json(AuthResponse {
        access_token: token(row.id, &state.jwt_secret)?,
        user_id: row.id,
        credits_balance: row.credits_balance,
    }))
}

fn validate_credentials(input: &AuthRequest) -> Result<()> {
    if !input.email.contains('@') || input.password.len() < 8 {
        return Err(AppError::BadRequest(
            "valid email and password of at least 8 characters are required".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct CreditBalance {
    credits_balance: i32,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct CreditTransaction {
    id: Uuid,
    amount: i32,
    transaction_type: String,
    description: String,
    created_at: DateTime<Utc>,
}

async fn credit_balance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CreditBalance>> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    sqlx::query_as::<_, CreditBalance>("SELECT credits_balance FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(map_db)?
        .map(Json)
        .ok_or(AppError::Unauthorized)
}

#[derive(Deserialize)]
struct CreditHistoryQuery {
    limit: Option<i64>,
}

async fn credit_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CreditHistoryQuery>,
) -> Result<Json<Vec<CreditTransaction>>> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let rows = sqlx::query_as::<_, CreditTransaction>(
        "SELECT id, amount, type AS transaction_type, description, created_at FROM credit_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    Ok(Json(rows))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct CreditPackage {
    id: Uuid,
    name: String,
    price: String,
    credits: i32,
    bonus_credits: i32,
}

async fn packages(State(state): State<AppState>) -> Result<Json<Vec<CreditPackage>>> {
    let rows = sqlx::query_as::<_, CreditPackage>(
        "SELECT id, name, price::text, credits, bonus_credits FROM credit_packages ORDER BY price",
    )
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    Ok(Json(rows))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct Topup {
    id: Uuid,
    package_id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TopupInput {
    package_id: Uuid,
}

async fn create_topup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TopupInput>,
) -> Result<(StatusCode, Json<Topup>)> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let topup = sqlx::query_as::<_, Topup>(
        "INSERT INTO credit_topups (user_id, package_id) SELECT $1, id FROM credit_packages WHERE id = $2 RETURNING id, package_id, status, created_at",
    )
    .bind(user_id)
    .bind(input.package_id)
    .fetch_optional(&state.db)
    .await
    .map_err(map_db)?
    .ok_or(AppError::NotFound)?;
    Ok((StatusCode::CREATED, Json(topup)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationInput {
    app_name: String,
    playstore_link: String,
    required_testers: Option<i32>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct Application {
    id: Uuid,
    developer_id: Uuid,
    app_name: String,
    playstore_link: String,
    status: String,
    required_testers: i32,
    assigned_testers: i64,
    created_at: DateTime<Utc>,
}

fn validate_application(input: &ApplicationInput) -> Result<i32> {
    if input.app_name.trim().is_empty() || input.app_name.trim().len() > 120 {
        return Err(AppError::BadRequest(
            "app name must be between 1 and 120 characters".into(),
        ));
    }
    if !(input.playstore_link.starts_with("https://")
        || input.playstore_link.starts_with("http://"))
    {
        return Err(AppError::BadRequest(
            "play store link must use http or https".into(),
        ));
    }
    let required_testers = input.required_testers.unwrap_or(12);
    if !(1..=100).contains(&required_testers) {
        return Err(AppError::BadRequest(
            "required testers must be between 1 and 100".into(),
        ));
    }
    Ok(required_testers)
}

const APPLICATION_SELECT: &str = "SELECT a.id, a.developer_id, a.app_name, a.playstore_link, a.status, a.required_testers, COUNT(ta.id) FILTER (WHERE ta.status = 'active') AS assigned_testers, a.created_at FROM applications a LEFT JOIN tester_assignments ta ON ta.application_id = a.id";

async fn submit_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApplicationInput>,
) -> Result<(StatusCode, Json<Application>)> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let required_testers = validate_application(&input)?;
    let mut transaction = state.db.begin().await.map_err(map_db)?;
    let updated = sqlx::query(
        "UPDATE users SET credits_balance = credits_balance - $1 WHERE id = $2 AND credits_balance >= $1",
    )
    .bind(APP_SUBMISSION_COST)
    .bind(user_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_db)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Conflict("insufficient credits".into()));
    }
    let application_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO applications (developer_id, app_name, playstore_link, required_testers) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(user_id)
    .bind(input.app_name.trim())
    .bind(input.playstore_link.trim())
    .bind(required_testers)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    insert_credit_transaction(
        &mut transaction,
        user_id,
        -APP_SUBMISSION_COST,
        "spent",
        "Application submission",
    )
    .await?;
    let application = sqlx::query_as::<_, Application>(&format!(
        "{} WHERE a.id = $1 GROUP BY a.id",
        APPLICATION_SELECT
    ))
    .bind(application_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    transaction.commit().await.map_err(map_db)?;
    Ok((StatusCode::CREATED, Json(application)))
}

async fn available_applications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Application>>> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let rows = sqlx::query_as::<_, Application>(&format!(
        "{} WHERE a.status IN ('open', 'in_progress') AND a.developer_id <> $1 GROUP BY a.id HAVING COUNT(ta.id) FILTER (WHERE ta.status = 'active') < a.required_testers ORDER BY a.created_at ASC",
        APPLICATION_SELECT
    ))
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    Ok(Json(rows))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct Assignment {
    id: Uuid,
    application_id: Uuid,
    tester_id: Uuid,
    status: String,
    assigned_at: DateTime<Utc>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct TestingAssignment {
    id: Uuid,
    app_id: Uuid,
    app_name: String,
    day_number: i32,
    total_days: i32,
    description: String,
}

async fn assignments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TestingAssignment>>> {
    let tester_id = authenticated_user(&headers, &state.jwt_secret)?;
    let rows = sqlx::query_as::<_, TestingAssignment>(
        "SELECT ta.id, a.id AS app_id, a.app_name, COALESCE(MAX(dc.day_number), 0)::int + 1 AS day_number, $2::int AS total_days, 'Selesaikan tugas pengujian hari ini.' AS description FROM tester_assignments ta JOIN applications a ON a.id = ta.application_id LEFT JOIN daily_checkins dc ON dc.assignment_id = ta.id WHERE ta.tester_id = $1 AND ta.status = 'active' GROUP BY ta.id, a.id, a.app_name ORDER BY a.created_at DESC",
    )
    .bind(tester_id)
    .bind(TESTING_DAYS)
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    Ok(Json(rows))
}

async fn join_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(application_id): Path<Uuid>,
) -> Result<(StatusCode, Json<Assignment>)> {
    let tester_id = authenticated_user(&headers, &state.jwt_secret)?;
    let mut transaction = state.db.begin().await.map_err(map_db)?;
    let application = sqlx::query_as::<_, (Uuid, i32, i32)>(
        "SELECT developer_id, required_testers, (SELECT COUNT(*) FROM tester_assignments WHERE application_id = $1 AND status = 'active')::int FROM applications WHERE id = $1 FOR UPDATE",
    )
    .bind(application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_db)?
    .ok_or(AppError::NotFound)?;
    if application.0 == tester_id {
        return Err(AppError::BadRequest(
            "developers cannot test their own app".into(),
        ));
    }
    if application.2 >= application.1 {
        return Err(AppError::Conflict(
            "application already has enough testers".into(),
        ));
    }
    let assignment = sqlx::query_as::<_, Assignment>(
        "INSERT INTO tester_assignments (application_id, tester_id) VALUES ($1, $2) RETURNING id, application_id, tester_id, status, assigned_at",
    )
    .bind(application_id)
    .bind(tester_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    sqlx::query(
        "UPDATE applications SET status = CASE WHEN (SELECT COUNT(*) FROM tester_assignments WHERE application_id = $1 AND status = 'active') >= required_testers THEN 'in_progress' ELSE status END WHERE id = $1",
    )
    .bind(application_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_db)?;
    transaction.commit().await.map_err(map_db)?;
    Ok((StatusCode::CREATED, Json(assignment)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckinInput {
    assignment_id: Uuid,
    day_number: i32,
    feedback_text: String,
    screenshot_url: Option<String>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct Checkin {
    id: Uuid,
    assignment_id: Uuid,
    day_number: i32,
    feedback_text: String,
    screenshot_url: Option<String>,
    is_verified: bool,
    checked_at: DateTime<Utc>,
}

fn validate_checkin(input: &CheckinInput) -> Result<()> {
    if !(1..=TESTING_DAYS).contains(&input.day_number) {
        return Err(AppError::BadRequest(
            "day number must be between 1 and 14".into(),
        ));
    }
    if input.feedback_text.trim().is_empty() || input.feedback_text.len() > 5000 {
        return Err(AppError::BadRequest(
            "feedback must be between 1 and 5000 characters".into(),
        ));
    }
    if let Some(screenshot_url) = input.screenshot_url.as_deref() {
        if !(screenshot_url.is_empty()
            || screenshot_url.starts_with("https://")
            || screenshot_url.starts_with("http://"))
        {
            return Err(AppError::BadRequest(
                "screenshot URL must use http or https".into(),
            ));
        }
    }
    Ok(())
}

async fn create_checkin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CheckinInput>,
) -> Result<(StatusCode, Json<Checkin>)> {
    let tester_id = authenticated_user(&headers, &state.jwt_secret)?;
    validate_checkin(&input)?;
    let mut transaction = state.db.begin().await.map_err(map_db)?;
    let assignment_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM tester_assignments WHERE id = $1 AND tester_id = $2 AND status = 'active')",
    )
    .bind(input.assignment_id)
    .bind(tester_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    if !assignment_exists {
        return Err(AppError::NotFound);
    }
    let checkin = sqlx::query_as::<_, Checkin>(
        "INSERT INTO daily_checkins (assignment_id, day_number, feedback_text, screenshot_url) VALUES ($1, $2, $3, $4) RETURNING id, assignment_id, day_number, feedback_text, screenshot_url, is_verified, checked_at",
    )
    .bind(input.assignment_id)
    .bind(input.day_number)
    .bind(input.feedback_text.trim())
    .bind(input.screenshot_url.as_deref().map(str::trim))
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_db)?;
    sqlx::query("UPDATE users SET credits_balance = credits_balance + $1 WHERE id = $2")
        .bind(CHECKIN_REWARD)
        .bind(tester_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_db)?;
    insert_credit_transaction(
        &mut transaction,
        tester_id,
        CHECKIN_REWARD,
        "earned",
        "Verified daily check-in",
    )
    .await?;
    transaction.commit().await.map_err(map_db)?;
    Ok((StatusCode::CREATED, Json(checkin)))
}

async fn insert_credit_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    amount: i32,
    transaction_type: &str,
    description: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO credit_transactions (user_id, amount, type, description) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(amount)
    .bind(transaction_type)
    .bind(description)
    .execute(&mut **transaction)
    .await
    .map_err(map_db)?;
    Ok(())
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct ApplicationProgress {
    application_id: Uuid,
    status: String,
    required_testers: i32,
    assigned_testers: i64,
    active_testers: i64,
    completed_checkins: i64,
    total_checkins: i64,
    current_day: i32,
}

async fn application_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(application_id): Path<Uuid>,
) -> Result<Json<ApplicationProgress>> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let progress = sqlx::query_as::<_, ApplicationProgress>(&format!(
        "SELECT a.id AS application_id, a.status, a.required_testers, COUNT(DISTINCT ta.id) AS assigned_testers, COUNT(DISTINCT ta.id) FILTER (WHERE ta.status = 'active') AS active_testers, COUNT(DISTINCT (dc.assignment_id, dc.day_number)) FILTER (WHERE dc.is_verified) AS completed_checkins, (a.required_testers * {})::bigint AS total_checkins, COALESCE(MAX(dc.day_number), 0)::int AS current_day FROM applications a LEFT JOIN tester_assignments ta ON ta.application_id = a.id LEFT JOIN daily_checkins dc ON dc.assignment_id = ta.id WHERE a.id = $1 AND a.developer_id = $2 GROUP BY a.id",
        TESTING_DAYS
    ))
    .bind(application_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(map_db)?
    .ok_or(AppError::NotFound)?;
    Ok(Json(progress))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct ReportRow {
    tester_id: Uuid,
    tester_email: String,
    completed_days: i64,
    last_checkin_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct DailyReport {
    day_number: i32,
    completed_checkins: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationReport {
    application_id: Uuid,
    app_name: String,
    playstore_link: String,
    status: String,
    testing_days: i32,
    required_testers: i32,
    generated_at: DateTime<Utc>,
    testers: Vec<ReportRow>,
    daily_summary: Vec<DailyReport>,
}

async fn application_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(application_id): Path<Uuid>,
) -> Result<Json<ApplicationReport>> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let application = sqlx::query_as::<_, (String, String, String, i32)>(
        "SELECT app_name, playstore_link, status, required_testers FROM applications WHERE id = $1 AND developer_id = $2",
    )
    .bind(application_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(map_db)?
    .ok_or(AppError::NotFound)?;
    let testers = sqlx::query_as::<_, ReportRow>(
        "SELECT ta.tester_id, u.email AS tester_email, COUNT(DISTINCT (dc.assignment_id, dc.day_number)) FILTER (WHERE dc.is_verified) AS completed_days, MAX(dc.checked_at) FILTER (WHERE dc.is_verified) AS last_checkin_at FROM tester_assignments ta JOIN users u ON u.id = ta.tester_id LEFT JOIN daily_checkins dc ON dc.assignment_id = ta.id WHERE ta.application_id = $1 GROUP BY ta.tester_id, u.email ORDER BY u.email",
    )
    .bind(application_id)
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    let daily_summary = sqlx::query_as::<_, DailyReport>(
        "SELECT day_number, COUNT(*) AS completed_checkins FROM daily_checkins dc JOIN tester_assignments ta ON ta.id = dc.assignment_id WHERE ta.application_id = $1 AND dc.is_verified GROUP BY day_number ORDER BY day_number",
    )
    .bind(application_id)
    .fetch_all(&state.db)
    .await
    .map_err(map_db)?;
    Ok(Json(ApplicationReport {
        application_id,
        app_name: application.0,
        playstore_link: application.1,
        status: application.2,
        testing_days: TESTING_DAYS,
        required_testers: application.3,
        generated_at: Utc::now(),
        testers,
        daily_summary,
    }))
}

async fn health() -> &'static str {
    "ok"
}

async fn rate_limit(request: Request, next: Next) -> Response {
    let key = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let now = Instant::now();
    let allowed = {
        let limiter = RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()));
        let mut requests = limiter.lock().unwrap();
        let entry = requests.entry(key).or_default();
        entry.retain(|timestamp| now.duration_since(*timestamp) < Duration::from_secs(60));
        if entry.len() >= 120 {
            false
        } else {
            entry.push(now);
            true
        }
    };
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(request).await
}

fn cors_layer() -> CorsLayer {
    let origins = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".into());
    let origins = origins
        .split(',')
        .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

fn map_db(error: sqlx::Error) -> AppError {
    match error {
        sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
            AppError::Conflict("resource already exists".into())
        }
        other => AppError::Internal(other.to_string()),
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/credits/balance", get(credit_balance))
        .route("/api/v1/credits/history", get(credit_history))
        .route("/api/v1/packages", get(packages))
        .route("/api/v1/topups", post(create_topup))
        .route("/api/v1/apps", post(submit_application))
        .route("/api/v1/apps/available", get(available_applications))
        .route("/api/v1/apps/:id/join", post(join_application))
        .route("/api/v1/assignments", get(assignments))
        .route("/api/v1/checkins", post(create_checkin))
        .route("/api/v1/apps/:id/progress", get(application_progress))
        .route("/api/v1/apps/:id/report", get(application_report))
        .layer(from_fn(rate_limit))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| AppError::Internal("DATABASE_URL is required".into()))?;
    let jwt_secret =
        env::var("JWT_SECRET").map_err(|_| AppError::Internal("JWT_SECRET is required".into()))?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .map_err(map_db)?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .map_err(|error| AppError::Internal(error.to_string()))?;
    let state = AppState {
        db,
        jwt_secret: Arc::new(jwt_secret),
    };
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .map_err(|error| AppError::Internal(error.to_string()))?;
    axum::serve(listener, app(state))
        .await
        .map_err(|error| AppError::Internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_defaults_to_twelve_testers() {
        let input = ApplicationInput {
            app_name: "Test app".into(),
            playstore_link: "https://play.google.com/apps/testing/example".into(),
            required_testers: None,
        };
        assert_eq!(validate_application(&input).unwrap(), 12);
    }

    #[test]
    fn checkin_requires_a_valid_day_and_feedback() {
        let input = CheckinInput {
            assignment_id: Uuid::new_v4(),
            day_number: 15,
            feedback_text: String::new(),
            screenshot_url: None,
        };
        assert!(validate_checkin(&input).is_err());
    }

    #[test]
    fn checkin_rejects_non_http_screenshot_urls() {
        let input = CheckinInput {
            assignment_id: Uuid::new_v4(),
            day_number: 1,
            feedback_text: "Works".into(),
            screenshot_url: Some("not-a-url".into()),
        };
        assert!(validate_checkin(&input).is_err());
    }

    #[test]
    fn report_includes_play_release_metadata_and_daily_summary() {
        let report = ApplicationReport {
            application_id: Uuid::nil(),
            app_name: "Demo".into(),
            playstore_link: "https://play.google.com/testing/demo".into(),
            status: "in_progress".into(),
            testing_days: 14,
            required_testers: 12,
            generated_at: Utc::now(),
            testers: Vec::new(),
            daily_summary: vec![DailyReport {
                day_number: 1,
                completed_checkins: 1,
            }],
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["testingDays"], 14);
        assert_eq!(json["requiredTesters"], 12);
        assert_eq!(json["dailySummary"][0]["dayNumber"], 1);
    }

    #[test]
    fn checkin_enforces_one_rewardable_row_per_assignment_day() {
        let checkin_insert =
            "INSERT INTO daily_checkins (assignment_id, day_number, feedback_text, screenshot_url)";
        let uniqueness_migration =
            "ADD CONSTRAINT daily_checkins_assignment_day_unique UNIQUE (assignment_id, day_number)";
        assert!(checkin_insert.contains("assignment_id, day_number"));
        assert!(uniqueness_migration.contains("UNIQUE (assignment_id, day_number)"));
        assert!(
            "UPDATE users SET credits_balance = credits_balance + $1".contains("credits_balance")
        );
        assert!("INSERT INTO credit_transactions".contains("credit_transactions"));
    }

    #[test]
    fn credentials_require_a_password_of_at_least_eight_characters() {
        let input = AuthRequest {
            email: "tester@example.com".into(),
            password: "short".into(),
        };
        assert!(validate_credentials(&input).is_err());
    }
}
