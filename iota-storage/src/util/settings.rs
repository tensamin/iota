use crate::storage_error::StorageError;
use crate::util::db;
use rusqlite::{OptionalExtension, params};

pub const GLOBAL_SESSION_ID: i64 = 0;
const GLOBAL_SETTINGS_NAME: &str = "__global__";

pub fn save(user_id: i64, session_id: i64, name: &str, payload: &str) -> Result<(), StorageError> {
    db::with_db(|conn| {
        conn.execute(
            "INSERT INTO settings (user_id, session_id, name, payload) VALUES (?1, ?2, ?3, ?4)\n             ON CONFLICT(user_id, session_id, name) DO UPDATE SET payload = excluded.payload",
            params![user_id, session_id, name, payload],
        )?;
        Ok(())
    })
}

pub fn load(user_id: i64, session_id: i64, name: &str) -> Result<Option<String>, StorageError> {
    db::with_db(|conn| {
        conn.query_row(
            "SELECT payload FROM settings WHERE user_id = ?1 AND session_id = ?2 AND name = ?3",
            params![user_id, session_id, name],
            |row| row.get(0),
        )
        .optional()
        .map_err(StorageError::from)
    })
}

pub fn list(user_id: i64, session_id: i64) -> Result<Vec<String>, StorageError> {
    db::with_db(|conn| {
        let mut statement = conn.prepare(
            "SELECT name FROM settings WHERE user_id = ?1 AND session_id = ?2 ORDER BY name",
        )?;
        let rows = statement.query_map(params![user_id, session_id], |row| row.get(0))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(StorageError::from)
    })
}

pub fn save_global(user_id: i64, payload: &str) -> Result<(), StorageError> {
    save(user_id, GLOBAL_SESSION_ID, GLOBAL_SETTINGS_NAME, payload)
}

pub fn load_global(user_id: i64) -> Result<Option<String>, StorageError> {
    load(user_id, GLOBAL_SESSION_ID, GLOBAL_SETTINGS_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn settings_schema_supports_user_and_session_keys() -> Result<(), StorageError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE settings (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (user_id, session_id, name)
            );",
        )?;

        conn.execute(
            "INSERT INTO settings VALUES (?1, ?2, ?3, ?4)",
            params![7, 11, "theme", "dark"],
        )?;
        conn.execute(
            "INSERT INTO settings VALUES (?1, ?2, ?3, ?4)",
            params![7, 12, "theme", "light"],
        )?;

        let payload: String = conn.query_row(
            "SELECT payload FROM settings WHERE user_id = 7 AND session_id = 11 AND name = 'theme'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(payload, "dark");

        Ok(())
    }
}
