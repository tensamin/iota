use std::{collections::BTreeMap, path::Path, process::Command};

use iota_storage::util::db;

fn files(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            (
                entry.file_name().to_str().unwrap().to_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn probe(directory: &Path, mode: &str, backup: &Path) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "startup_refuses_corruption_prior_recovery_and_future_schemas_until_explicit_restore",
            "--nocapture",
        ])
        .env("IOTA_RECOVERY_PROBE_DIRECTORY", directory)
        .env("IOTA_RECOVERY_PROBE_MODE", mode)
        .env("IOTA_RECOVERY_PROBE_BACKUP", backup)
        .status()
        .unwrap();
    assert!(status.success(), "startup probe failed in mode {mode}");
}

#[test]
fn startup_refuses_corruption_prior_recovery_and_future_schemas_until_explicit_restore() {
    if let Ok(directory) = std::env::var("IOTA_RECOVERY_PROBE_DIRECTORY") {
        let directory = std::path::PathBuf::from(directory);
        iota_util::file_util::configure_storage_directory(directory.clone());
        match std::env::var("IOTA_RECOVERY_PROBE_MODE").unwrap().as_str() {
            "seed" => {
                db::initialize_database().unwrap();
                db::with_db(|connection| {
                    connection.execute_batch("CREATE TABLE recovery_fixture(value TEXT NOT NULL); INSERT INTO recovery_fixture VALUES('retained-account-state');")?;
                    Ok(())
                }).unwrap();
                db::backup_encrypted_storage(Path::new(
                    &std::env::var("IOTA_RECOVERY_PROBE_BACKUP").unwrap(),
                ))
                .unwrap();
            }
            "refuse" => {
                assert!(
                    db::verify_and_backup_database()
                        .and_then(|()| db::initialize_database())
                        .is_err()
                );
                assert!(db::pool().is_err());
            }
            "future" => {
                assert!(
                    db::verify_and_backup_database()
                        .unwrap_err()
                        .to_string()
                        .contains("newer than supported")
                );
                assert!(
                    db::initialize_database()
                        .unwrap_err()
                        .to_string()
                        .contains("newer than supported")
                );
                assert!(db::pool().is_err());
            }
            "restored" => {
                db::verify_and_backup_database()
                    .and_then(|()| db::initialize_database())
                    .unwrap();
                let value: String = db::with_db(|connection| {
                    Ok(connection
                        .query_row("SELECT value FROM recovery_fixture", [], |row| row.get(0))?)
                })
                .unwrap();
                assert_eq!(value, "retained-account-state");
            }
            mode => panic!("unknown startup probe {mode}"),
        }
        return;
    }

    let temporary = tempfile::tempdir().unwrap();
    let backup = temporary.path().join("backup");
    probe(&temporary.path().join("original"), "seed", &backup);

    let corrupt = temporary.path().join("corrupt");
    std::fs::create_dir(&corrupt).unwrap();
    std::fs::write(
        corrupt.join("messages.sqlite3"),
        b"deliberately-corrupt-disposable-database",
    )
    .unwrap();
    let before = files(&corrupt);
    for _ in 0..2 {
        probe(&corrupt, "refuse", &backup);
    }
    assert_eq!(files(&corrupt), before);

    let prior_recovery = temporary.path().join("prior-recovery");
    let recovery = prior_recovery.join("recovery");
    std::fs::create_dir_all(&recovery).unwrap();
    std::fs::copy(
        backup.join("messages.sqlite3"),
        recovery.join("messages.sqlite3.retained"),
    )
    .unwrap();
    let retained = files(&recovery);
    for _ in 0..2 {
        probe(&prior_recovery, "refuse", &backup);
    }
    assert!(!prior_recovery.join("messages.sqlite3").exists());
    assert_eq!(files(&recovery), retained);

    let future = temporary.path().join("future");
    std::fs::create_dir(&future).unwrap();
    std::fs::copy(
        backup.join("messages.sqlite3"),
        future.join("messages.sqlite3"),
    )
    .unwrap();
    let connection = rusqlite::Connection::open(future.join("messages.sqlite3")).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=74;")
        .unwrap();
    drop(connection);
    let before = files(&future);
    for _ in 0..2 {
        probe(&future, "future", &backup);
    }
    assert_eq!(files(&future), before);

    let restored = temporary.path().join("restored");
    db::restore_encrypted_storage(&backup, &restored).unwrap();
    probe(&restored, "restored", &backup);
    assert_eq!(
        files(&corrupt),
        BTreeMap::from([(
            "messages.sqlite3".into(),
            b"deliberately-corrupt-disposable-database".to_vec()
        )])
    );
}
