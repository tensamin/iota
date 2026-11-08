use crate::{storage_error::StorageError, util::db};
use iota_identity::{
    HostedAuthorizationLease, LocalUserId, PrincipalHandle, ValidatedHostedIdentity,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

static CHANGES: once_cell::sync::Lazy<tokio::sync::watch::Sender<u64>> =
    once_cell::sync::Lazy::new(|| tokio::sync::watch::channel(0).0);
static REVOKED_CONNECTIONS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = once_cell::sync::Lazy::new(Default::default);

pub fn changes() -> tokio::sync::watch::Receiver<u64> {
    CHANGES.subscribe()
}

pub(crate) fn notify_change() {
    CHANGES.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedAuthState {
    pub local_user: LocalUserId,
    pub generation: i64,
    pub enabled: bool,
}

pub fn current(user: LocalUserId) -> Result<HostedAuthState, StorageError> {
    db::with_db(|connection| current_in_db(connection, user))
}

fn current_in_db(
    connection: &Connection,
    user: LocalUserId,
) -> Result<HostedAuthState, StorageError> {
    connection
        .query_row(
            "SELECT generation, enabled FROM hosted_auth_state WHERE local_user_id = ?1",
            [user.0],
            |row| {
                Ok(HostedAuthState {
                    local_user: user,
                    generation: row.get(0)?,
                    enabled: row.get(1)?,
                })
            },
        )
        .optional()?
        .ok_or(StorageError::HostedAuthorizationDenied)
}

pub fn revoke_in_tx(
    tx: &Transaction<'_>,
    user: LocalUserId,
) -> Result<HostedAuthState, StorageError> {
    let state = current_in_db(tx, user)?;
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::HostedGenerationExhausted)?;
    if tx.execute("UPDATE hosted_auth_state SET generation = ?2, enabled = 0 WHERE local_user_id = ?1 AND generation = ?3",
        params![user.0, generation, state.generation])? != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    current_in_db(tx, user)
}

pub fn revoke(user: LocalUserId) -> Result<HostedAuthState, StorageError> {
    db::with_immediate_transaction(|tx| revoke_in_tx(tx, user))
}

/// One SQL statement supplies the account key, principal, residency and generation snapshot.
pub fn resolve(user: LocalUserId) -> Result<(ValidatedHostedIdentity, String), StorageError> {
    db::with_db(|connection| {
        connection
            .query_row(
                "SELECT h.principal_handle, a.generation, u.public_key FROM users u
             JOIN hosted_auth_state a ON a.local_user_id = u.user_id
             JOIN hosted_principals h ON h.local_user_id = u.user_id
             JOIN principals p ON p.principal_pk = h.principal_handle
             LEFT JOIN user_residency r ON r.user_id = u.user_id
             WHERE u.user_id = ?1 AND a.enabled = 1 AND p.retired_at IS NULL
               AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
                [user.0],
                |row| {
                    Ok((
                        ValidatedHostedIdentity {
                            local_user: user,
                            principal: PrincipalHandle(row.get(0)?),
                            auth_generation: row.get(1)?,
                        },
                        row.get(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::HostedAuthorizationDenied)
    })
}

pub fn register(lease: &HostedAuthorizationLease) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| register_in_tx(tx, lease))
}

fn register_in_tx(
    tx: &Transaction<'_>,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    let cancelled: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosted_forwarded_revocations WHERE connection_id=?1)",
        [&lease.connection_id],
        |row| row.get(0),
    )?;
    if cancelled {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    let identity = lease.identity;
    let inserted = tx.execute(
        "INSERT INTO hosted_connection_authorizations
             (connection_id, server_instance, local_user_id, principal_handle, auth_generation)
             SELECT ?1, ?2, a.local_user_id, h.principal_handle, a.generation
             FROM hosted_auth_state a JOIN users u ON u.user_id = a.local_user_id
             JOIN hosted_principals h ON h.local_user_id = a.local_user_id
             JOIN principals p ON p.principal_pk = h.principal_handle
             LEFT JOIN user_residency r ON r.user_id = u.user_id
             WHERE a.local_user_id = ?3 AND h.principal_handle = ?4
               AND a.generation = ?5 AND a.enabled = 1 AND p.retired_at IS NULL
               AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
        params![
            lease.connection_id,
            lease.server_instance,
            identity.local_user.0,
            identity.principal.0,
            identity.auth_generation
        ],
    )?;
    if inserted != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    Ok(())
}

pub fn verify_in_tx(
    tx: &Transaction<'_>,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    verify_in_db(tx, lease)
}

fn verify_in_db(
    connection: &Connection,
    lease: &HostedAuthorizationLease,
) -> Result<(), StorageError> {
    if REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .contains(&lease.connection_id)
    {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    let identity = lease.identity;
    let valid: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM hosted_connection_authorizations s
         JOIN hosted_auth_state a ON a.local_user_id = s.local_user_id
         JOIN hosted_principals h ON h.local_user_id = s.local_user_id
         JOIN users u ON u.user_id = s.local_user_id
         JOIN principals p ON p.principal_pk = h.principal_handle
         JOIN hosted_server_instances owner ON owner.server_instance = s.server_instance
         LEFT JOIN user_residency r ON r.user_id = u.user_id
         WHERE s.connection_id = ?1 AND s.server_instance = ?2
           AND s.local_user_id = ?3 AND s.principal_handle = ?4 AND s.auth_generation = ?5
            AND owner.expires_at > unixepoch() AND s.revoked = 0 AND a.enabled = 1 AND a.generation = s.auth_generation
           AND h.principal_handle = s.principal_handle AND p.retired_at IS NULL
           AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed'))",
        params![
            lease.connection_id,
            lease.server_instance,
            identity.local_user.0,
            identity.principal.0,
            identity.auth_generation
        ],
        |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(StorageError::HostedAuthorizationDenied)
    }
}

pub fn verify(lease: &HostedAuthorizationLease) -> Result<(), StorageError> {
    db::with_db(|connection| verify_in_db(connection, lease))
}

/// A stopped owner cannot renew an expired lease or revive its authorizations.
pub fn maintain_server(instance: &str, start: bool) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| maintain_server_in_tx(tx, instance, start))
}

fn maintain_server_in_tx(
    tx: &Transaction<'_>,
    instance: &str,
    start: bool,
) -> Result<(), StorageError> {
    if start {
        tx.execute(
            "INSERT OR IGNORE INTO hosted_server_instances VALUES (?1, unixepoch() + 60)",
            [instance],
        )?;
    }
    if tx.execute("UPDATE hosted_server_instances SET expires_at = unixepoch() + 60 WHERE server_instance = ?1 AND expires_at > unixepoch()", [instance])? != 1 {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    tx.execute("UPDATE hosted_connection_authorizations SET revoked = 1 WHERE revoked = 0 AND NOT EXISTS (SELECT 1 FROM hosted_server_instances owner WHERE owner.server_instance = hosted_connection_authorizations.server_instance AND owner.expires_at > unixepoch())", [])?;
    Ok(())
}

/// One statement verifies the complete active set, including exact lease bindings.
pub fn verify_batch(leases: &[HostedAuthorizationLease]) -> Result<Vec<String>, StorageError> {
    db::with_db(|connection| verify_batch_in_db(connection, leases))
}

fn verify_batch_in_db(
    connection: &Connection,
    leases: &[HostedAuthorizationLease],
) -> Result<Vec<String>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT s.connection_id, s.server_instance, s.local_user_id, s.principal_handle, s.auth_generation
         FROM hosted_connection_authorizations s
         JOIN hosted_server_instances owner ON owner.server_instance = s.server_instance
         JOIN hosted_auth_state a ON a.local_user_id = s.local_user_id
         JOIN hosted_principals h ON h.local_user_id = s.local_user_id
         JOIN users u ON u.user_id = s.local_user_id
         JOIN principals p ON p.principal_pk = h.principal_handle
         LEFT JOIN user_residency r ON r.user_id = u.user_id
         WHERE owner.expires_at > unixepoch() AND s.revoked = 0 AND a.enabled = 1
           AND a.generation = s.auth_generation AND h.principal_handle = s.principal_handle
           AND p.retired_at IS NULL AND (r.lifecycle_state IS NULL OR r.lifecycle_state = 'managed')",
    )?;
    let valid = statement
        .query_map([], |row| {
            Ok(HostedAuthorizationLease {
                connection_id: row.get(0)?,
                server_instance: row.get(1)?,
                identity: ValidatedHostedIdentity {
                    local_user: LocalUserId(row.get(2)?),
                    principal: PrincipalHandle(row.get(3)?),
                    auth_generation: row.get(4)?,
                },
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let valid = valid
        .into_iter()
        .map(|lease| (lease.connection_id.clone(), lease))
        .collect::<std::collections::HashMap<_, _>>();
    let revoked = REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned");
    Ok(leases
        .iter()
        .filter(|lease| {
            revoked.contains(&lease.connection_id) || valid.get(&lease.connection_id) != Some(lease)
        })
        .map(|lease| lease.connection_id.clone())
        .collect())
}

pub fn remove(connection_id: &str) -> Result<(), StorageError> {
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .insert(connection_id.to_owned());
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE hosted_connection_authorizations SET revoked = 1 WHERE connection_id = ?1",
            [connection_id],
        )?;
        Ok(())
    })?;
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .remove(connection_id);
    Ok(())
}

/// Cancel a server-generated forwarding nonce even if registration has not yet
/// happened. The tombstone has no account/principal dependency and survives
/// restart. A successful return fences every subsequent actual application commit.
pub fn revoke_forwarded(connection_id: &str) -> Result<(), StorageError> {
    if connection_id
        .strip_prefix("omikron-relay:")
        .and_then(|nonce| uuid::Uuid::parse_str(nonce).ok())
        .is_none_or(|nonce| connection_id != format!("omikron-relay:{nonce}"))
    {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .insert(connection_id.to_owned());
    db::with_immediate_transaction(|tx| revoke_forwarded_in_tx(tx, connection_id))?;
    REVOKED_CONNECTIONS
        .lock()
        .expect("revocation lock poisoned")
        .remove(connection_id);
    Ok(())
}

pub fn revoke_forwarded_in_tx(
    tx: &Transaction<'_>,
    connection_id: &str,
) -> Result<(), StorageError> {
    let nonce = connection_id
        .strip_prefix("omikron-relay:")
        .and_then(|nonce| uuid::Uuid::parse_str(nonce).ok())
        .filter(|nonce| connection_id == format!("omikron-relay:{nonce}"));
    if nonce.is_none() {
        return Err(StorageError::HostedAuthorizationDenied);
    }
    let inserted=tx.execute("INSERT INTO hosted_forwarded_revocations(connection_id,revoked_at) VALUES(?1,?2) ON CONFLICT(connection_id) DO NOTHING",params![connection_id,crate::util::sync::now_millis()])?;
    let revoked=tx.execute("UPDATE hosted_connection_authorizations SET revoked=1 WHERE connection_id=?1 AND revoked=0",[connection_id])?;
    if inserted != 0 || revoked != 0 {
        tx.execute(
            "UPDATE hosted_auth_changes SET sequence=sequence+1 WHERE singleton=1",
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(connection: &Connection) {
        db::initialize_schema(connection).unwrap();
        connection.execute_batch(
            "INSERT INTO users(user_id,username,public_key,created_at,display_name) VALUES (7, 'alice', 'key', 0, 'Alice');
             INSERT INTO user_residency(user_id,username,lifecycle_state,data_state,updated_at) VALUES (7, 'alice', 'managed', 'present', 0);
             INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,home,last_resolved_at) VALUES (9, 'iota', 'local', 7, 'local', 0), (10, 'iota', 'other', 8, 'other', 0);
             INSERT INTO hosted_principals VALUES (7, 9);"
        ).unwrap();
        connection
            .execute(
                "INSERT INTO hosted_server_instances VALUES ('instance', unixepoch() + 60)",
                [],
            )
            .unwrap();
    }

    fn lease(connection: &mut Connection) -> HostedAuthorizationLease {
        let lease = HostedAuthorizationLease {
            connection_id: "connection".into(),
            server_instance: "instance".into(),
            identity: ValidatedHostedIdentity {
                local_user: LocalUserId(7),
                principal: PrincipalHandle(9),
                auth_generation: current_in_db(connection, LocalUserId(7))
                    .unwrap()
                    .generation,
            },
        };
        let tx = connection.transaction().unwrap();
        register_in_tx(&tx, &lease).unwrap();
        tx.commit().unwrap();
        lease
    }

    #[test]
    fn forwarded_cancellation_before_registration_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("forwarded.sqlite3");
        let mut connection = Connection::open(&path).unwrap();
        setup(&connection);
        let mut forwarded = lease(&mut connection);
        forwarded.connection_id = "omikron-relay:00000000-0000-4000-8000-000000000001".into();
        let tx = connection.transaction().unwrap();
        revoke_forwarded_in_tx(&tx, &forwarded.connection_id).unwrap();
        tx.commit().unwrap();
        drop(connection);
        let mut connection = Connection::open(path).unwrap();
        let tx = connection.transaction().unwrap();
        assert!(matches!(
            register_in_tx(&tx, &forwarded),
            Err(StorageError::HostedAuthorizationDenied)
        ));
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM hosted_connection_authorizations WHERE local_user_id=0",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert!(
            tx.execute("DELETE FROM hosted_forwarded_revocations", [])
                .is_err()
        );
        tx.rollback().unwrap();
    }

    #[test]
    fn forwarded_cancellation_fences_existing_exact_lease_and_is_atomic() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let mut forwarded = lease(&mut connection);
        forwarded.connection_id = "omikron-relay:00000000-0000-4000-8000-000000000002".into();
        let tx = connection.transaction().unwrap();
        register_in_tx(&tx, &forwarded).unwrap();
        tx.commit().unwrap();
        let tx = connection.transaction().unwrap();
        verify_in_tx(&tx, &forwarded).unwrap();
        revoke_forwarded_in_tx(&tx, &forwarded.connection_id).unwrap();
        assert!(matches!(
            verify_in_tx(&tx, &forwarded),
            Err(StorageError::HostedAuthorizationDenied)
        ));
        tx.rollback().unwrap();
        let tx = connection.transaction().unwrap();
        verify_in_tx(&tx, &forwarded).unwrap();
        revoke_forwarded_in_tx(&tx, &forwarded.connection_id).unwrap();
        revoke_forwarded_in_tx(&tx, &forwarded.connection_id).unwrap();
        tx.commit().unwrap();
        assert!(matches!(
            verify_in_db(&connection, &forwarded),
            Err(StorageError::HostedAuthorizationDenied)
        ));
    }

    #[test]
    fn reconciliation_preserves_live_other_owners_and_fences_expired_owners() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let live = lease(&mut connection);
        let mut other = live.clone();
        other.connection_id = "other-connection".into();
        other.server_instance = "other-instance".into();
        let tx = connection.transaction().unwrap();
        maintain_server_in_tx(&tx, "other-instance", true).unwrap();
        register_in_tx(&tx, &other).unwrap();
        tx.commit().unwrap();
        assert!(
            verify_batch_in_db(&connection, &[live.clone(), other.clone()])
                .unwrap()
                .is_empty()
        );
        connection.execute("UPDATE hosted_server_instances SET expires_at = 0 WHERE server_instance = 'instance'", []).unwrap();
        assert_eq!(
            verify_batch_in_db(&connection, &[live.clone(), other.clone()]).unwrap(),
            vec![live.connection_id.clone()]
        );
        let tx = connection.transaction().unwrap();
        assert!(maintain_server_in_tx(&tx, "instance", false).is_err());
        maintain_server_in_tx(&tx, "other-instance", false).unwrap();
        tx.commit().unwrap();
        assert!(verify_in_db(&connection, &live).is_err());
        verify_in_db(&connection, &other).unwrap();
        let revoked: bool = connection.query_row("SELECT revoked FROM hosted_connection_authorizations WHERE connection_id = 'connection'", [], |row| row.get(0)).unwrap();
        assert!(revoked);
    }

    #[test]
    fn batch_checks_exact_generation_and_durable_connection_revocation() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let live = lease(&mut connection);
        let mut stale = live.clone();
        stale.identity.auth_generation += 1;
        assert_eq!(
            verify_batch_in_db(&connection, &[stale]).unwrap(),
            vec![live.connection_id.clone()]
        );
        connection
            .execute(
                "UPDATE hosted_connection_authorizations SET revoked = 1",
                [],
            )
            .unwrap();
        assert!(verify_in_db(&connection, &live).is_err());
        assert_eq!(
            verify_batch_in_db(&connection, std::slice::from_ref(&live)).unwrap(),
            vec![live.connection_id]
        );
    }

    #[test]
    fn authority_changes_revoke_clones_but_profile_changes_do_not() {
        for mutation in [
            "UPDATE users SET public_key = 'rotated' WHERE user_id = 7",
            "UPDATE user_residency SET lifecycle_state = 'released' WHERE user_id = 7",
            "UPDATE hosted_principals SET principal_handle = 10 WHERE local_user_id = 7",
            "DELETE FROM hosted_principals WHERE local_user_id = 7",
            "UPDATE principals SET home = 'new-home' WHERE principal_pk = 9",
            "DELETE FROM users WHERE user_id = 7",
        ] {
            let mut connection = Connection::open_in_memory().unwrap();
            setup(&connection);
            let lease = lease(&mut connection);
            connection
                .execute(
                    "UPDATE users SET display_name = 'New name' WHERE user_id = 7",
                    [],
                )
                .unwrap();
            verify_in_db(&connection, &lease).unwrap();
            connection.execute(mutation, []).unwrap();
            assert!(matches!(
                verify_in_db(&connection, &lease),
                Err(StorageError::HostedAuthorizationDenied)
            ));
            assert!(
                current_in_db(&connection, LocalUserId(7))
                    .unwrap()
                    .generation
                    > 1
            );
        }
    }

    #[test]
    fn stale_admission_and_generation_reuse_are_rejected() {
        let mut connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        let stale = lease(&mut connection);
        connection
            .execute("DELETE FROM users WHERE user_id = 7", [])
            .unwrap();
        connection
            .execute("INSERT INTO users(user_id,username,public_key,created_at,display_name) VALUES (7, 'alice', 'key', 0, 'Alice')", [])
            .unwrap();
        let tx = connection.transaction().unwrap();
        let mut pending = stale.clone();
        pending.connection_id = "pending".into();
        assert!(matches!(
            register_in_tx(&tx, &pending),
            Err(StorageError::HostedAuthorizationDenied)
        ));
        assert!(verify_in_tx(&tx, &stale).is_err());
    }

    #[test]
    fn exhausted_generation_rolls_back_key_rotation() {
        let connection = Connection::open_in_memory().unwrap();
        setup(&connection);
        connection
            .execute(
                "UPDATE hosted_auth_state SET generation = ?1 WHERE local_user_id = 7",
                [i64::MAX],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE users SET public_key = 'rotated' WHERE user_id = 7",
                    []
                )
                .is_err()
        );
        let key: String = connection
            .query_row(
                "SELECT public_key FROM users WHERE user_id = 7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(key, "key");
    }

    #[test]
    fn external_revocation_and_acceptance_have_database_ordering() {
        use std::sync::{Arc, Barrier};
        for acceptance_first in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("authority.sqlite3");
            let mut connection = Connection::open(&path).unwrap();
            setup(&connection);
            let lease = lease(&mut connection);
            let ready = Arc::new(Barrier::new(2));
            let committed = Arc::new(Barrier::new(2));
            let writer = std::thread::spawn({
                let ready = ready.clone();
                let committed = committed.clone();
                move || {
                    let mut external = Connection::open(path).unwrap();
                    external
                        .busy_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    ready.wait();
                    let tx = external
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                        .unwrap();
                    revoke_in_tx(&tx, LocalUserId(7)).unwrap();
                    tx.commit().unwrap();
                    committed.wait();
                }
            });
            if !acceptance_first {
                ready.wait();
                committed.wait();
            }
            let tx = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            if acceptance_first {
                ready.wait();
            }
            let authorized = verify_in_tx(&tx, &lease);
            if authorized.is_ok() {
                crate::util::relay_replay::reserve_in_tx(
                    &tx,
                    crate::util::relay_replay::RelayReservationRequest {
                        signer_principal: PrincipalHandle(9),
                        signer_id: 7,
                        message_id: "operation",
                        created_at: 1,
                        accepted_at: 2,
                        destination_id: 8,
                        frame: b"exact verified operation",
                        frame_id: 1,
                        type_map_version: "1.0",
                    },
                )
                .unwrap();
            }
            assert_eq!(authorized.is_ok(), acceptance_first);
            tx.commit().unwrap();
            if acceptance_first {
                committed.wait();
            }
            writer.join().unwrap();
            assert!(verify_in_db(&connection, &lease).is_err());
            let count: i64 = connection
                .query_row("SELECT COUNT(*) FROM relay_inbox", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, i64::from(acceptance_first));
        }
    }
}
