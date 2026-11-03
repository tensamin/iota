use super::*;

pub(super) fn migrate(conn: &Connection, current_version: i64) -> Result<(), StorageError> {
    if current_version >= 71 {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    // ALTER TABLE also validates unrelated legacy trigger references. Rebuild
    // only this table while keeping its records inside the same transaction.
    tx.execute_batch(
        "CREATE TEMP TABLE federation_authorities_previous AS SELECT * FROM federation_authorities;
        DROP TABLE federation_authorities;",
    )?;
    tx.execute_batch(crate::authority_directory::SCHEMA)?;
    tx.execute_batch("INSERT INTO federation_authorities(authority_id,locator,node_id,discovered_at,verified_at,source,is_preferred)
        SELECT authority_id,locator,node_id,discovered_at,verified_at,source,is_preferred FROM federation_authorities_previous;
        DROP TABLE temp.federation_authorities_previous;
        PRAGMA user_version = 71;")?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_iota_pins_and_adds_distinct_omega_provenance() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            &crate::authority_directory::SCHEMA.replace("node_id TEXT,", "node_id TEXT NOT NULL,"),
        )
        .unwrap();
        conn.execute("INSERT INTO federation_authorities VALUES('iota-authority','iota.example','iota-node',1,2,'https_domain',1)", []).unwrap();
        migrate(&conn, 70).unwrap();
        let retained: (String, i64, i64, i64) = conn.query_row("SELECT node_id,discovered_at,verified_at,is_preferred FROM federation_authorities WHERE locator='iota.example'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
        assert_eq!(retained, ("iota-node".into(), 1, 2, 1));
        conn.execute("INSERT INTO federation_authorities VALUES('omega-authority','omega.example',NULL,3,4,'https_domain',0)", []).unwrap();
        migrate(&conn, 71).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM federation_authorities", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            71
        );
    }
}
