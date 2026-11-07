//! Expiring SQLite read transactions pin a sync boundary without copying an
//! entire account before its first page. They never occupy the application pool.
use super::*;
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{Duration, Instant},
};

struct View {
    connection: Arc<Mutex<Connection>>,
    owner: i64,
    expires: Instant,
}

struct Views {
    entries: Mutex<HashMap<String, View>>,
    changed: Condvar,
}

fn unavailable() -> StorageError {
    protocol_error(SyncError::Retryable)
}

fn views() -> Result<&'static Arc<Views>, StorageError> {
    static VIEWS: OnceLock<Result<Arc<Views>, std::io::Error>> = OnceLock::new();
    VIEWS
        .get_or_init(|| {
            let views = Arc::new(Views {
                entries: Mutex::new(HashMap::new()),
                changed: Condvar::new(),
            });
            let worker = views.clone();
            std::thread::Builder::new()
                .name("sync-view-expiry".into())
                .spawn(move || {
                    let Ok(mut entries) = worker.entries.lock() else {
                        return;
                    };
                    loop {
                        // Closing the read connection releases its WAL checkpoint pin,
                        // including when no further application requests arrive.
                        entries.retain(|_, view| view.expires > Instant::now());
                        let wake = entries.values().map(|view| view.expires).min();
                        entries = match wake {
                            Some(wake) => match worker.changed.wait_timeout(
                                entries,
                                wake.saturating_duration_since(Instant::now()),
                            ) {
                                Ok((entries, _)) => entries,
                                Err(_) => return,
                            },
                            None => match worker.changed.wait(entries) {
                                Ok(entries) => entries,
                                Err(_) => return,
                            },
                        };
                    }
                })?;
            Ok(views)
        })
        .as_ref()
        .map_err(|error| StorageError::Other(error.to_string()))
}

pub(super) fn capture(
    tx: &Transaction<'_>,
    id: &str,
    owner: i64,
    head: i64,
) -> Result<(), StorageError> {
    let views = views()?;
    let mut entries = views.entries.lock().map_err(|_| unavailable())?;
    entries.retain(|_, view| view.expires > Instant::now());
    let mut obsolete = Vec::new();
    for id in entries.keys() {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_sync_pages WHERE id=?1)",
            [id],
            |row| row.get(0),
        )?;
        if !exists {
            obsolete.push(id.clone());
        }
    }
    for id in obsolete {
        entries.remove(&id);
    }
    // This limits simultaneous pinned readers, never account size.
    if entries.len() >= 64 || entries.values().filter(|view| view.owner == owner).count() >= 4 {
        return Err(protocol_error(SyncError::Capacity));
    }
    let path = tx.path().ok_or_else(unavailable)?;
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_millis(250))?;
    connection.execute_batch("BEGIN DEFERRED")?;
    let pinned_head: i64 = connection
        .query_row(
            "SELECT version FROM sync_heads WHERE user_id=?1",
            [owner],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if pinned_head != head {
        return Err(protocol_error(SyncError::SnapshotRequired));
    }
    entries.insert(
        id.into(),
        View {
            connection: Arc::new(Mutex::new(connection)),
            owner,
            expires: Instant::now() + Duration::from_millis(TTL_MS as u64),
        },
    );
    views.changed.notify_one();
    Ok(())
}

pub(super) fn read<T>(
    id: &str,
    read: impl FnOnce(&Connection) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    let connection = {
        let views = views()?;
        let entries = views.entries.lock().map_err(|_| unavailable())?;
        let view = entries
            .get(id)
            .filter(|view| view.expires > Instant::now())
            .ok_or_else(|| protocol_error(SyncError::SnapshotRequired))?;
        view.connection.clone()
    };
    let connection = connection.lock().map_err(|_| unavailable())?;
    read(&connection)
}

pub(super) fn remove(id: &str) {
    if let Ok(views) = views() {
        if let Ok(mut entries) = views.entries.lock() {
            entries.remove(id);
        }
        views.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_reader_survives_writes_and_lost_or_expired_views_require_a_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let mut connection = Connection::open(directory.path().join("views.sqlite3")).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
            CREATE TABLE sync_heads(user_id INTEGER PRIMARY KEY,version INTEGER NOT NULL);
            INSERT INTO sync_heads VALUES(7,1);
            CREATE TABLE account_sync_pages(id TEXT PRIMARY KEY);",
            )
            .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute("INSERT INTO account_sync_pages VALUES(?1)", [&id])
            .unwrap();
        capture(&transaction, &id, 7, 1).unwrap();
        transaction.commit().unwrap();
        connection
            .execute("UPDATE sync_heads SET version=2", [])
            .unwrap();
        let pinned = read(&id, |connection| {
            Ok(connection.query_row(
                "SELECT version FROM sync_heads WHERE user_id=7",
                [],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .unwrap();
        assert_eq!(pinned, 1);
        views()
            .unwrap()
            .entries
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .expires = Instant::now();
        assert!(matches!(
            read(&id, |_| Ok(())),
            Err(StorageError::InvalidRelayPayload("sync_snapshot_required"))
        ));
        remove(&id);
        assert!(matches!(
            read(&id, |_| Ok(())),
            Err(StorageError::InvalidRelayPayload("sync_snapshot_required"))
        ));
        let busy: i64 = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy, 0);
    }
}
