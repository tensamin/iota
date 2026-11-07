use super::*;
use rusqlite::OptionalExtension;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 73 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='principal_keys')",
        [],
        |row| row.get(0),
    )?;
    if exists {
        add_table_column_if_missing(&tx, "principal_keys", "key_id", "key_id TEXT")?;
        let mut position = 0i64;
        loop {
            let row: Option<(i64, Option<String>)> = tx.query_row(
            "SELECT rowid,CASE WHEN typeof(public_key)='text' AND length(public_key)<=262144 THEN public_key ELSE NULL END
             FROM principal_keys WHERE rowid>?1 AND key_id IS NULL ORDER BY rowid LIMIT 1", [position],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
            let Some((rowid, encoded)) = row else { break };
            position = rowid;
            // Preserve malformed legacy records, but never index them as verified keys.
            let Some(key_id) = encoded
                .as_deref()
                .and_then(iota_util::crypto_helper::public_key_bundle_from_base64)
                .and_then(|key| iota_identity::file_signing_key_id(&key).ok())
            else {
                continue;
            };
            tx.execute(
                "UPDATE principal_keys SET key_id=?2 WHERE rowid=?1",
                rusqlite::params![rowid, key_id],
            )?;
        }
        tx.execute_batch("CREATE INDEX IF NOT EXISTS principal_file_signing_key ON principal_keys(principal_pk,key_id);")?;
    }
    tx.pragma_update(None, "user_version", 73)?;
    tx.commit()?;
    Ok(())
}
