use super::*;

mod identity;
mod relay_transactions;

#[test]
fn old_storage_format_requires_a_fresh_database_without_resetting_it() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .pragma_update(None, "application_id", 0x49544F31_i64)
        .unwrap();
    connection
        .execute_batch("CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('keep');")
        .unwrap();
    let error = verify_storage_format(&connection).unwrap_err();
    assert!(error.to_string().contains("initialize a fresh database"));
    assert_eq!(
        connection
            .query_row("SELECT value FROM marker", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "keep"
    );
}
