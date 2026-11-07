//! Durable snapshot coverage. Retained until owner erasure, never age-pruned.
use crate::storage_error::StorageError;
use rusqlite::{Connection, Transaction, params};

pub const PAGE_LIMIT: usize = 128;
pub const SCHEMA: &str = "
CREATE TABLE relay_acceptance_receipts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 storage_owner INTEGER NOT NULL,
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 accepted_at INTEGER NOT NULL,
 UNIQUE(storage_owner, signer_principal, message_id)
);
CREATE INDEX relay_acceptance_receipts_owner_sequence
 ON relay_acceptance_receipts(storage_owner, sequence);
CREATE TABLE relay_receipt_backfill_blocks (
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 storage_owner INTEGER NOT NULL,
 reason TEXT NOT NULL,
 PRIMARY KEY(signer_principal, message_id, storage_owner)
);
CREATE INDEX relay_receipt_backfill_blocks_owner ON relay_receipt_backfill_blocks(storage_owner);";

pub fn backfill_block_count() -> Result<i64, StorageError> {
    super::db::with_db(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM relay_receipt_backfill_blocks",
            [],
            |row| row.get(0),
        )?)
    })
}

/// Invalid persisted operations block receipt publication when ownership is unknown.
pub fn block_backfill_for_record_on(
    conn: &Connection,
    signer: i64,
    message_id: &str,
) -> Result<(), StorageError> {
    conn.execute("INSERT INTO relay_receipt_backfill_blocks(signer_principal,message_id,storage_owner,reason)
        VALUES(?1,?2,0,'invalid_persisted_operation') ON CONFLICT DO NOTHING", params![signer, message_id])?;
    Ok(())
}

fn ensure_backfill_complete_on(conn: &Connection, owner: i64) -> Result<(), StorageError> {
    let blocked: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_receipt_backfill_blocks WHERE storage_owner IN (0, ?1))",
        [owner],
        |row| row.get(0),
    )?;
    if blocked {
        return Err(StorageError::Other(
            "receipt_backfill_incomplete: persisted coverage requires operator repair".into(),
        ));
    }
    Ok(())
}

pub fn insert_in_tx(
    tx: &Transaction<'_>,
    owner: i64,
    signer: i64,
    message_id: &str,
    accepted_at: i64,
) -> Result<(), StorageError> {
    tx.execute("INSERT INTO relay_acceptance_receipts(storage_owner, signer_principal, message_id, accepted_at)
        VALUES (?1, ?2, ?3, ?4) ON CONFLICT(storage_owner, signer_principal, message_id) DO NOTHING",
        params![owner, signer, message_id, accepted_at])?;
    let matches: bool = tx.query_row(
        "SELECT accepted_at = ?4 FROM relay_acceptance_receipts
        WHERE storage_owner = ?1 AND signer_principal = ?2 AND message_id = ?3",
        params![owner, signer, message_id, accepted_at],
        |row| row.get(0),
    )?;
    if !matches {
        return Err(StorageError::PendingRelayConflict);
    }
    Ok(())
}

#[derive(Debug)]
pub struct Receipt {
    pub sequence: i64,
    pub principal: String,
    pub message_id: String,
    pub accepted_at: i64,
}

#[derive(Debug)]
pub struct ReceiptPage {
    pub cursor: i64,
    pub upper: i64,
    pub more: bool,
    pub records: Vec<Receipt>,
}

pub fn upper_on(conn: &Connection, owner: i64) -> Result<i64, StorageError> {
    ensure_backfill_complete_on(conn, owner)?;
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM relay_acceptance_receipts WHERE storage_owner = ?1",
        [owner],
        |row| row.get(0),
    )?)
}

pub fn receipt_page_on(
    conn: &Connection,
    owner: i64,
    after: i64,
    upper: i64,
    limit: usize,
) -> Result<ReceiptPage, StorageError> {
    if after < 0 || upper < after || limit == 0 || limit > PAGE_LIMIT {
        return Err(StorageError::InvalidRelayPayload("receipt page bounds"));
    }
    if upper > upper_on(conn, owner)? {
        return Err(StorageError::InvalidRelayPayload(
            "receipt upper exceeds owner boundary",
        ));
    }
    let mut statement = conn.prepare(
        "SELECT r.sequence, p.authority_id, p.remote_user_id, r.message_id, r.accepted_at
        FROM relay_acceptance_receipts r LEFT JOIN principals p ON p.principal_pk = r.signer_principal
        WHERE r.storage_owner = ?1 AND r.sequence > ?2 AND r.sequence <= ?3
        ORDER BY r.sequence LIMIT ?4",
    )?;
    let mut records = statement
        .query_map(params![owner, after, upper, (limit + 1) as i64], |row| {
            let authority: String = row.get(1)?;
            let user_id: i64 = row.get(2)?;
            Ok(Receipt {
                sequence: row.get(0)?,
                principal: serde_json::json!({"authority": authority, "user_id": user_id})
                    .to_string(),
                message_id: row.get(3)?,
                accepted_at: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let more = records.len() > limit;
    records.truncate(limit);
    let cursor = if more {
        records.last().expect("nonempty bounded page").sequence
    } else {
        upper
    };
    Ok(ReceiptPage {
        cursor,
        upper,
        more,
        records,
    })
}

pub fn receipt_page(
    owner: i64,
    after: i64,
    upper: Option<i64>,
    limit: usize,
) -> Result<ReceiptPage, StorageError> {
    super::db::with_db(|conn| {
        let tx = conn.unchecked_transaction()?;
        let page = receipt_page_on(
            &tx,
            owner,
            after,
            upper.map_or_else(|| upper_on(&tx, owner), Ok)?,
            limit,
        )?;
        tx.commit()?;
        Ok(page)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE principals(principal_pk INTEGER PRIMARY KEY, authority_id TEXT, remote_user_id INTEGER);
            INSERT INTO principals VALUES(7, 'peer', 99);
            CREATE TABLE users(user_id INTEGER PRIMARY KEY);
            INSERT INTO users VALUES(1); INSERT INTO users VALUES(2);
            CREATE TABLE hosted_principals(local_user_id INTEGER, principal_handle INTEGER);
            INSERT INTO hosted_principals VALUES(1, 11); INSERT INTO hosted_principals VALUES(2, 22);
            CREATE TABLE relay_inbox(signer_principal INTEGER, message_id TEXT, accepted_at INTEGER, state TEXT, prepared_operation BLOB);").unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn
    }

    #[test]
    fn publication_is_atomic_and_conflicting_metadata_rolls_back() {
        let mut conn = database();
        {
            let tx = conn.transaction().unwrap();
            tx.execute("INSERT INTO users VALUES(3)", []).unwrap();
            insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
            // Simulate failure after application and receipt publication.
        }
        assert_eq!(upper_on(&conn, 1).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM users WHERE user_id=3", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
        insert_in_tx(&tx, 1, 7, "operation", 123).unwrap();
        tx.commit().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO users VALUES(3)", []).unwrap();
        assert!(matches!(
            insert_in_tx(&tx, 1, 7, "operation", 124),
            Err(StorageError::PendingRelayConflict)
        ));
        tx.rollback().unwrap();
        assert_eq!(
            receipt_page_on(&conn, 1, 0, upper_on(&conn, 1).unwrap(), 128)
                .unwrap()
                .records
                .len(),
            1
        );
    }

    #[test]
    fn pages_are_bounded_indexed_and_ignore_concurrent_acceptance_and_history() {
        let mut conn = database();
        let tx = conn.transaction().unwrap();
        for n in 0..385 {
            insert_in_tx(&tx, 1, 7, &format!("operation-{n}"), n).unwrap();
        }
        insert_in_tx(&tx, 2, 7, "other-owner", 400).unwrap();
        tx.commit().unwrap();
        let upper = upper_on(&conn, 1).unwrap();
        // History is deliberately unreadable. Live reads must use only the
        // normalized receipt index, even after inbox pruning or codec changes.
        conn.execute(
            "INSERT INTO relay_inbox VALUES(7,'broken',1,'applied',x'ffff')",
            [],
        )
        .unwrap();
        let first = receipt_page_on(&conn, 1, 0, upper, 128).unwrap();
        assert_eq!(first.records.len(), 128);
        assert!(first.more);
        let tx = conn.transaction().unwrap();
        insert_in_tx(&tx, 1, 7, "concurrent", 401).unwrap();
        tx.commit().unwrap();
        let mut cursor = first.cursor;
        let mut sequences = first.records.iter().map(|r| r.sequence).collect::<Vec<_>>();
        loop {
            let page = receipt_page_on(&conn, 1, cursor, upper, 128).unwrap();
            assert!(page.records.len() <= 128);
            sequences.extend(page.records.iter().map(|r| r.sequence));
            cursor = page.cursor;
            if !page.more {
                break;
            }
        }
        assert_eq!(cursor, upper);
        assert_eq!(sequences.len(), 385);
        assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
        let later = receipt_page_on(&conn, 1, upper, upper_on(&conn, 1).unwrap(), 128).unwrap();
        assert_eq!(later.records[0].message_id, "concurrent");
        assert!(receipt_page_on(&conn, 1, 0, upper, 129).is_err());
        let plan: String = conn.query_row("EXPLAIN QUERY PLAN SELECT sequence FROM relay_acceptance_receipts WHERE storage_owner=1 AND sequence>0 AND sequence<=100 ORDER BY sequence LIMIT 129", [], |row| row.get(3)).unwrap();
        assert!(
            plan.contains("relay_acceptance_receipts_owner_sequence"),
            "{plan}"
        );
    }
}
