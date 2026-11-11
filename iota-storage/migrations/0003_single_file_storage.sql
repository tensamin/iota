CREATE TEMP TABLE retained_file_ids (id INTEGER PRIMARY KEY);
INSERT INTO retained_file_ids
SELECT id FROM (
    SELECT file.id, ROW_NUMBER() OVER (
        PARTITION BY file.storage_user_id, file.origin_principal, file.file_id
        ORDER BY CASE WHEN file.state = 'ready' AND file.asset_id IS NOT NULL AND (
            hosted.principal_handle IS NULL OR file.origin_principal = hosted.principal_handle OR (
                origin.retired_at IS NULL AND EXISTS (
                    SELECT 1 FROM file_share_grants grant
                    WHERE grant.storage_user_id = file.storage_user_id
                      AND grant.origin_principal = file.origin_principal
                      AND grant.file_id = file.file_id AND grant.version = file.version
                      AND grant.recipient_principal = hosted.principal_handle
                      AND grant.state = 'accepted'
                      AND grant.expires_at > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
                ) AND NOT EXISTS (
                    SELECT 1 FROM blocked_users blocked
                    WHERE blocked.user_id = file.storage_user_id AND blocked.blocked_principal = file.origin_principal
                )
            )
        ) THEN 1 ELSE 0 END DESC, file.version DESC
    ) AS position
    FROM files file
    LEFT JOIN hosted_principals hosted ON hosted.local_user_id = file.storage_user_id
    LEFT JOIN principals origin ON origin.principal_pk = file.origin_principal
) WHERE position = 1;

DELETE FROM file_replication_jobs WHERE file_row_id NOT IN (SELECT id FROM retained_file_ids);
DELETE FROM files WHERE id NOT IN (SELECT id FROM retained_file_ids);
DROP TABLE retained_file_ids;

UPDATE file_changes SET kind = 'retired', payload = '{}'
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
