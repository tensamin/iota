use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 72 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "DELETE FROM account_sync_pages;
        CREATE TABLE IF NOT EXISTS account_sync_page_progress (
            page_id TEXT PRIMARY KEY,
            table_index INTEGER NOT NULL DEFAULT 0,
            row_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TRIGGER IF NOT EXISTS account_sync_progress_delete AFTER DELETE ON account_sync_pages BEGIN
            DELETE FROM account_sync_page_progress WHERE page_id=OLD.id;
        END;
        PRAGMA user_version=72;",
    )?;
    for (table, owner) in [
        ("messages", "storage_owner"),
        ("contacts", "storage_owner"),
        ("synced_settings", "user_id"),
        ("user_blobs", "user_id"),
        ("user_assets", "user_id"),
        ("blocked_users", "user_id"),
    ] {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            tx.execute_batch(&format!(
                "CREATE INDEX IF NOT EXISTS sync_snapshot_{table} ON {table}({owner},id);"
            ))?;
        }
    }
    let epochs:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_secret_epochs')",[],|row|row.get(0))?;
    if epochs {
        tx.execute_batch(
            "CREATE INDEX IF NOT EXISTS sync_snapshot_epochs_first ON chat_secret_epochs(first_principal);
        CREATE INDEX IF NOT EXISTS sync_snapshot_epochs_second ON chat_secret_epochs(second_principal);",
        )?;
    }
    tx.commit()?;
    Ok(())
}
