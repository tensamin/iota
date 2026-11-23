use super::*;

pub fn edit_message(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        body,
        true,
    )
}

pub fn edit_message_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        true,
    )
}

pub fn edit_message_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        true,
        None,
    )
}

/* Applies an edit received from the message sender to the recipient's copy. */
pub fn apply_remote_edit(
    storage_owner: i64,
    external_user: i64,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }

    update_message_content(
        storage_owner,
        external_user,
        None,
        message_time,
        editor_id,
        body,
        false,
    )
}

/// VersionNumber identifies the replacement ciphertext's key, as used by the
/// client's encryptChatText/decryptChatText calls. It may be an older available
/// epoch or a new epoch, independent of the original message's key version.
/// The relay calls require_edit_key_in_tx with the authenticated chat first.
/// See client/packages/chat/src/components/message.tsx and context.tsx in the
/// sibling client repository for edit production and live decryption.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn edit_message_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
    key_version: i64,
) -> Result<(), StorageError> {
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        true,
        Some(key_version),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit edit identity, key version and caller transaction"
)]
pub fn apply_remote_edit_for_principal_versioned_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
    key_version: i64,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        false,
        Some(key_version),
    )
}

/// Check the exact ciphertext epoch, rather than the latest chat secret. A
/// missing epoch is recoverable when its secret arrives, including after restart.
pub fn require_edit_key_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    chat_id: &str,
    key_version: i64,
) -> Result<(), StorageError> {
    if key_version <= 0 {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    crate::util::e2ee_storage::get_chat_secret_on(
        tx,
        &crate::util::e2ee_storage::ChatSecretQuery {
            user_id: storage_owner.to_string(),
            chat_id: chat_id.to_owned(),
            secret_id: Some(crate::util::e2ee_storage::principal_secret_id(chat_id)),
            version: Some(key_version),
        },
    )?
    .ok_or(StorageError::MissingRelayDependency)?;
    Ok(())
}

pub fn apply_remote_edit_for_principal(
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content(
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        false,
    )
}

pub(super) fn update_message_content(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
    require_sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        update_message_content_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            editor_id,
            body,
            require_sent_by_self,
            None,
        )
    })
}

pub fn apply_remote_edit_for_principal_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: iota_identity::PrincipalHandle,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
) -> Result<(), StorageError> {
    if editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    update_message_content_in_tx(
        tx,
        storage_owner,
        external_user,
        Some(external_principal),
        message_time,
        editor_id,
        body,
        false,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit message identity and caller transaction"
)]
pub(super) fn update_message_content_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    body: MessageBody<'_>,
    require_sent_by_self: bool,
    key_version: Option<i64>,
) -> Result<(), StorageError> {
    if key_version.is_some_and(|version| version <= 0) {
        return Err(StorageError::InvalidRelayPayload("edit key version"));
    }
    let Some(stored) = stored_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal,
        message_time,
        require_sent_by_self,
    )?
    else {
        return Ok(());
    };

    if parse_files(&stored.files)?
        .iter()
        .any(|file| file.status == Some(FileStatus::Uploading))
    {
        return Err(StorageError::InvalidRelayPayload("edit during upload"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let new_files = files_json(body.files)?;

    tx.execute(
        r#"
            INSERT INTO message_edits (message_id, content_before, content_after, files_before, files_after, edited_at, edited_by, content_before_key_version, content_after_key_version)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        params![stored.id, stored.content, body.content, stored.files, new_files, now, editor_id, stored.key_version, key_version.unwrap_or(stored.key_version)],
    )?;

    tx.execute(
        r#"
            UPDATE messages
            SET content = ?1, files = ?2, edited_count = edited_count + 1,
                key_version = COALESCE(?4, key_version), history_deleted=0, delivery_pruned=0, history_deleted_at=NULL
            WHERE id = ?3
            "#,
        params![body.content, new_files, stored.id, key_version],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        stored.id,
        Operation::Upsert,
    )?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit message identity and caller transaction"
)]
pub fn update_message_files_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    files: &[MessageFile],
    sent_by_self: bool,
) -> Result<(), StorageError> {
    if !sent_by_self && editor_id != external_user {
        return Err(StorageError::MessageUnauthorized);
    }
    let Some(stored) = stored_message_in_tx(
        tx,
        storage_owner,
        external_user,
        external_principal,
        message_time,
        sent_by_self,
    )?
    else {
        return Ok(());
    };

    if stored.history_deleted {
        return Err(StorageError::InvalidRelayPayload("file status transition"));
    }
    let current = parse_files(&stored.files)?;
    if current.len() != files.len()
        || current.iter().zip(files).any(|(old, new)| {
            old.reference != new.reference
                || (old.status != new.status && old.status != Some(FileStatus::Uploading))
        })
    {
        return Err(StorageError::InvalidRelayPayload("file status transition"));
    }
    tx.execute(
        "UPDATE messages SET files = ?1 WHERE id = ?2",
        params![files_json(files)?, stored.id],
    )?;
    sync::record_event(
        tx,
        storage_owner,
        EntityType::Message,
        stored.id,
        Operation::Upsert,
    )?;
    Ok(())
}

pub fn update_message_files(
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    editor_id: i64,
    files: &[MessageFile],
    sent_by_self: bool,
) -> Result<(), StorageError> {
    db::with_immediate_transaction(|tx| {
        update_message_files_in_tx(
            tx,
            storage_owner,
            external_user,
            external_principal,
            message_time,
            editor_id,
            files,
            sent_by_self,
        )
    })
}

fn parse_files(files: &str) -> Result<Vec<MessageFile>, StorageError> {
    serde_json::from_str(files).map_err(|error| StorageError::Other(error.to_string()))
}

struct StoredBody {
    id: i64,
    content: Option<Vec<u8>>,
    files: String,
    key_version: i64,
    history_deleted: bool,
}

fn stored_message_in_tx(
    tx: &Transaction<'_>,
    storage_owner: i64,
    external_user: i64,
    external_principal: Option<iota_identity::PrincipalHandle>,
    message_time: i64,
    require_sent_by_self: bool,
) -> Result<Option<StoredBody>, StorageError> {
    let identity = params![
        storage_owner,
        external_user,
        message_time,
        external_principal.map(|principal| principal.0),
        require_sent_by_self
    ];

    let found = tx
        .query_row(
            r#"
            SELECT id, content, files, key_version, history_deleted, delivery_pruned
            FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
              AND sent_by_self = ?5
              AND deleted_by_external = 0
            "#,
            identity,
            |row| {
                Ok((
                    StoredBody {
                        id: row.get(0)?,
                        content: row.get(1)?,
                        files: row.get(2)?,
                        key_version: row.get(3)?,
                        history_deleted: row.get::<_, i64>(4)? != 0,
                    },
                    row.get::<_, i64>(5)? != 0,
                ))
            },
        )
        .optional()?;
    let Some((stored, delivery_pruned)) = found else {
        let other_direction = tx.query_row(
            r#"
            SELECT EXISTS(SELECT 1 FROM messages
            WHERE storage_owner = ?1
              AND message_time = ?3
              AND (
                  (?4 IS NULL AND external_user = ?2)
                  OR external_principal = ?4
              )
              AND sent_by_self != ?5)
            "#,
            identity,
            |row| row.get::<_, bool>(0),
        )?;
        return Err(if other_direction {
            StorageError::MessageUnauthorized
        } else {
            StorageError::MissingRelayDependency
        });
    };
    if stored.history_deleted && !delivery_pruned {
        return Ok(None);
    }
    Ok(Some(stored))
}
