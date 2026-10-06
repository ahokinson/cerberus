//! cerberus's state database: a local turso file at `Paths::database_file`,
//! behind `audits.rs` (the opt-in decision record) and `violations.rs` (the
//! always-on per-session deny counts, which hold no command text).
//!
//! The decision record is two tables with different shapes on purpose. A deny or ask is rare and
//! worth keeping whole, so it's a row in `decisions`. An allow is the bulk of
//! traffic and already redacted down to tool, shape and directory, so it's
//! folded into a per-day counter in `allows` instead of one row per call.
//! That's what keeps the file small however busy the machine is, and why
//! retention is a `DELETE` by age rather than a log rotation that could push
//! the denies out along with the allows.
//!
//! turso holds an exclusive lock while a process has the database open, and
//! every hook invocation is its own process, so parallel tool calls collide.
//! [`retrying`] repeats an operation on that error for a short budget rather
//! than failing; past the budget the caller drops the record, per the audit
//! contract that a broken write never affects a guard decision.

use super::audits::AuditRecord;
use crate::config::Paths;
use serde_json::Value;
use std::fs;
use std::future::Future;
use std::time::Duration;
use turso::{Builder, Connection};

pub type Result<T> = std::result::Result<T, turso::Error>;

/// Rows older than this are deleted on the next write.
const RETENTION_SECS: i64 = 90 * 86400;
const SECS_PER_DAY: i64 = 86400;

/// How long an operation waits for another cerberus process to release the
/// database before giving up: `LOCK_RETRIES` tries `LOCK_BACKOFF` apart.
const LOCK_RETRIES: u32 = 100;
const LOCK_BACKOFF: Duration = Duration::from_millis(5);

/// One day's allowed calls of one tool, command shape and directory.
#[derive(Debug, Clone, PartialEq)]
pub struct AllowCount {
    pub day: u64,
    pub tool_name: String,
    pub shape: String,
    pub cwd: String,
    pub n: u64,
}

fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("building a tokio runtime")
        .block_on(fut)
}

/// Runs `op` again while it fails because another process (or thread) has the
/// database, for up to the lock budget. Any other error ends it at once.
async fn retrying<T, Fut: Future<Output = Result<T>>>(mut op: impl FnMut() -> Fut) -> Result<T> {
    let mut tries = 0;
    loop {
        match op().await {
            Err(e) if tries < LOCK_RETRIES && e.to_string().contains("locked") => {
                tries += 1;
                tokio::time::sleep(LOCK_BACKOFF).await;
            }
            done => return done,
        }
    }
}

async fn open(paths: &Paths) -> Result<Connection> {
    let path = paths.database_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| turso::Error::Misuse(e.to_string()))?;
    }
    let db = Builder::new_local(&path.to_string_lossy()).build().await?;
    let conn = db.connect()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS decisions (
            ts INTEGER NOT NULL, session_id TEXT, head TEXT NOT NULL, tool_name TEXT,
            decision TEXT NOT NULL, rule TEXT, reason TEXT, tool_input TEXT,
            harness TEXT NOT NULL, cwd TEXT, shape TEXT)",
        (),
    )
    .await?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS decisions_ts ON decisions (ts)",
        (),
    )
    .await?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS allows (
            day INTEGER NOT NULL, tool_name TEXT NOT NULL, shape TEXT NOT NULL,
            cwd TEXT NOT NULL, n INTEGER NOT NULL,
            PRIMARY KEY (day, tool_name, shape, cwd))",
        (),
    )
    .await?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS violations (
            session_id TEXT NOT NULL, head TEXT NOT NULL, n INTEGER NOT NULL, ts INTEGER NOT NULL,
            PRIMARY KEY (session_id, head))",
        (),
    )
    .await?;
    Ok(conn)
}

async fn prune(conn: &Connection, now: i64) -> Result<()> {
    let cutoff = now - RETENTION_SECS;
    conn.execute("DELETE FROM violations WHERE ts < ?1", (cutoff,))
        .await?;
    conn.execute("DELETE FROM decisions WHERE ts < ?1", (cutoff,))
        .await?;
    conn.execute(
        "DELETE FROM allows WHERE day < ?1",
        (cutoff / SECS_PER_DAY,),
    )
    .await?;
    Ok(())
}

/// Best-effort retention sweep after a write that already landed. A failure
/// here must not make the caller retry, which would count the write twice,
/// so it's dropped; the next write sweeps again.
fn prune_after(conn: &Connection, now: i64) {
    let _ = block_on(prune(conn, now));
}

pub fn insert_decision(paths: &Paths, r: &AuditRecord) -> Result<()> {
    let tool_input = (!r.tool_input.is_null()).then(|| r.tool_input.to_string());
    let conn = block_on(retrying(|| async {
        let conn = open(paths).await?;
        conn.execute(
            "INSERT INTO decisions
                (ts, session_id, head, tool_name, decision, rule, reason, tool_input, harness, cwd, shape)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            (
                r.ts as i64,
                r.session_id.clone(),
                r.head.clone(),
                r.tool_name.clone(),
                r.decision.clone(),
                r.rule.clone(),
                r.reason.clone(),
                tool_input.clone(),
                r.harness.clone(),
                r.cwd.clone(),
                r.shape.clone(),
            ),
        )
        .await?;
        Ok(conn)
    }))?;
    prune_after(&conn, r.ts as i64);
    Ok(())
}

/// Counts one allowed call. A missing tool, shape or directory is stored as
/// the empty string, since a primary-key column can't usefully be NULL.
pub fn bump_allow(
    paths: &Paths,
    ts: u64,
    tool_name: Option<&str>,
    shape: Option<&str>,
    cwd: Option<&str>,
) -> Result<()> {
    let conn = block_on(retrying(|| async {
        let conn = open(paths).await?;
        conn.execute(
            "INSERT INTO allows (day, tool_name, shape, cwd, n) VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT (day, tool_name, shape, cwd) DO UPDATE SET n = n + 1",
            (
                ts as i64 / SECS_PER_DAY,
                tool_name.unwrap_or(""),
                shape.unwrap_or(""),
                cwd.unwrap_or(""),
            ),
        )
        .await?;
        Ok(conn)
    }))?;
    prune_after(&conn, ts as i64);
    Ok(())
}

/// Counts one deny against a session's head. `ts` is the last update, which
/// is what retention sweeps on, so a long-running session keeps its counts.
pub fn bump_violation(paths: &Paths, session_id: &str, head: &str, ts: u64) -> Result<()> {
    let conn = block_on(retrying(|| async {
        let conn = open(paths).await?;
        conn.execute(
            "INSERT INTO violations (session_id, head, n, ts) VALUES (?1, ?2, 1, ?3)
             ON CONFLICT (session_id, head) DO UPDATE SET n = n + 1, ts = ?3",
            (session_id, head, ts as i64),
        )
        .await?;
        Ok(conn)
    }))?;
    prune_after(&conn, ts as i64);
    Ok(())
}

/// A session's `(head, count)` pairs; empty for an unseen session. Like the
/// other reads, never creates the database.
pub fn violations(paths: &Paths, session_id: &str) -> Result<Vec<(String, u64)>> {
    if !paths.database_file().exists() {
        return Ok(Vec::new());
    }
    block_on(retrying(|| async {
        let conn = open(paths).await?;
        let mut rows = conn
            .query(
                "SELECT head, n FROM violations WHERE session_id = ?1",
                (session_id,),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push((row.get(0)?, row.get::<i64>(1)? as u64));
        }
        Ok(out)
    }))
}

/// Every stored deny/ask, oldest first. No database yet means no decisions,
/// not an error, so reading never creates the file.
pub fn decisions(paths: &Paths) -> Result<Vec<AuditRecord>> {
    if !paths.database_file().exists() {
        return Ok(Vec::new());
    }
    block_on(retrying(|| async {
        let conn = open(paths).await?;
        let mut rows = conn
            .query(
                "SELECT ts, session_id, head, tool_name, decision, rule, reason,
                        tool_input, harness, cwd, shape
                 FROM decisions ORDER BY ts, rowid",
                (),
            )
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let tool_input: Option<String> = row.get(7)?;
            out.push(AuditRecord {
                ts: row.get::<i64>(0)? as u64,
                session_id: row.get(1)?,
                head: row.get(2)?,
                tool_name: row.get(3)?,
                decision: row.get(4)?,
                rule: row.get(5)?,
                reason: row.get(6)?,
                tool_input: tool_input
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(Value::Null),
                harness: row.get(8)?,
                cwd: row.get(9)?,
                shape: row.get(10)?,
            });
        }
        Ok(out)
    }))
}

/// Every day's allow counters, for `group`.
pub fn allows(paths: &Paths) -> Result<Vec<AllowCount>> {
    if !paths.database_file().exists() {
        return Ok(Vec::new());
    }
    block_on(retrying(|| async {
        let conn = open(paths).await?;
        let mut rows = conn
            .query("SELECT day, tool_name, shape, cwd, n FROM allows", ())
            .await?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(AllowCount {
                day: row.get::<i64>(0)? as u64,
                tool_name: row.get(1)?,
                shape: row.get(2)?,
                cwd: row.get(3)?,
                n: row.get::<i64>(4)? as u64,
            });
        }
        Ok(out)
    }))
}
