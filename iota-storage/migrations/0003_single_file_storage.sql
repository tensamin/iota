DELETE FROM file_replication_jobs
WHERE file_row_id IN (
    SELECT old.id FROM files old
    WHERE EXISTS (
        SELECT 1 FROM files current
        WHERE current.storage_user_id = old.storage_user_id
          AND current.origin_principal = old.origin_principal
          AND current.file_id = old.file_id AND current.version > old.version
    )
);

DELETE FROM files AS old
WHERE EXISTS (
    SELECT 1 FROM files current
    WHERE current.storage_user_id = old.storage_user_id
      AND current.origin_principal = old.origin_principal
      AND current.file_id = old.file_id AND current.version > old.version
);

DELETE FROM file_changes
WHERE COALESCE(json_extract(payload, '$.key'), json_extract(payload, '$.manifest.key')) IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM files file JOIN principals principal ON principal.principal_pk = file.origin_principal
      WHERE file.storage_user_id = file_changes.storage_user_id
        AND file.file_id = COALESCE(json_extract(payload, '$.key.file_id'), json_extract(payload, '$.manifest.key.file_id'))
        AND file.version = COALESCE(json_extract(payload, '$.key.version'), json_extract(payload, '$.manifest.key.version'))
        AND principal.authority_id = COALESCE(json_extract(payload, '$.key.origin.authority'), json_extract(payload, '$.manifest.key.origin.authority'))
        AND principal.remote_user_id = COALESCE(json_extract(payload, '$.key.origin.user_id'), json_extract(payload, '$.manifest.key.origin.user_id'))
  )
  AND NOT (
      kind = 'share_revoked' AND EXISTS (
          SELECT 1 FROM file_share_grants grant JOIN principals principal ON principal.principal_pk = grant.origin_principal
          JOIN principals recipient ON recipient.principal_pk = grant.recipient_principal
          WHERE grant.storage_user_id = file_changes.storage_user_id
            AND grant.file_id = json_extract(payload, '$.key.file_id')
            AND grant.version = json_extract(payload, '$.key.version')
            AND principal.authority_id = json_extract(payload, '$.key.origin.authority')
            AND principal.remote_user_id = json_extract(payload, '$.key.origin.user_id')
            AND recipient.authority_id = json_extract(payload, '$.recipient.authority')
            AND recipient.remote_user_id = json_extract(payload, '$.recipient.user_id')
            AND grant.chat_id = json_extract(payload, '$.chat_id')
      )
  );

UPDATE file_changes SET kind = 'file' WHERE kind = 'version';
CREATE UNIQUE INDEX files_identity ON files(storage_user_id, origin_principal, file_id);
