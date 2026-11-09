CREATE TABLE IF NOT EXISTS account_sync_checkpoints (
            user_id INTEGER NOT NULL, scope TEXT NOT NULL, sequence INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, PRIMARY KEY(user_id,scope)
         );

CREATE TABLE IF NOT EXISTS account_sync_floors(user_id INTEGER PRIMARY KEY, sequence INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS account_sync_page_items (
            page_id TEXT NOT NULL, position INTEGER NOT NULL, payload BLOB NOT NULL,
            PRIMARY KEY(page_id,position)
         );

CREATE TABLE IF NOT EXISTS account_sync_page_progress (
            page_id TEXT PRIMARY KEY,
            table_index INTEGER NOT NULL DEFAULT 0,
            row_id INTEGER NOT NULL DEFAULT 0
        );

CREATE TABLE IF NOT EXISTS account_sync_pages (
            id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, scope TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('snapshot','delta')), after_sequence INTEGER NOT NULL,
            head INTEGER NOT NULL, floor INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            item_count INTEGER NOT NULL DEFAULT 0, issued_through INTEGER NOT NULL DEFAULT 0
         );

CREATE TABLE IF NOT EXISTS "blocked_users" (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    blocked_user_id INTEGER NOT NULL,
                    blocked_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                    revision INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(user_id, blocked_principal)
                );

CREATE TABLE IF NOT EXISTS call_envelopes (
                recipient_id INTEGER NOT NULL,
                call_id TEXT NOT NULL,
                owner_omikron_id INTEGER NOT NULL,
                inviter_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                secret_id TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                encrypted_secret BLOB NOT NULL,
                kem_ciphertext BLOB NOT NULL,
                wrapping_scheme TEXT NOT NULL,
                PRIMARY KEY (recipient_id, call_id)
            );

CREATE TABLE IF NOT EXISTS call_epoch_envelopes (
        owner TEXT NOT NULL, call_id TEXT NOT NULL, recipient TEXT NOT NULL,
        user_id INTEGER NOT NULL, epoch INTEGER NOT NULL, local_user_id INTEGER NOT NULL,
        owner_omikron_id INTEGER NOT NULL, state TEXT NOT NULL,
        expires_at INTEGER NOT NULL, fingerprint BLOB, payload TEXT,
        PRIMARY KEY(owner, call_id, recipient, user_id, epoch)
    );

CREATE TABLE IF NOT EXISTS call_epoch_operations (
        owner TEXT NOT NULL, operation_id TEXT NOT NULL, fingerprint BLOB NOT NULL,
        PRIMARY KEY(owner, operation_id)
    );

CREATE TABLE IF NOT EXISTS chat_secret_changes (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    sequence INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_secret_epochs (
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    PRIMARY KEY(first_principal,second_principal,version)
);

CREATE TABLE IF NOT EXISTS chat_secret_erasure_fences (
    principal TEXT PRIMARY KEY NOT NULL,
    erased_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_secret_escrows (
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    evidence BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    signer TEXT NOT NULL,
    message_id TEXT NOT NULL,
    PRIMARY KEY(first_principal,second_principal,version)
);

CREATE TABLE IF NOT EXISTS chat_secret_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_owner INTEGER NOT NULL,
    owner_principal TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    secret_id TEXT NOT NULL,
    peer_principal TEXT NOT NULL,
    wrapping_chat_id TEXT NOT NULL,
    wrapping_secret_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    dispatched_at INTEGER,
    UNIQUE(storage_owner,owner_principal,chat_id,version)
);

CREATE TABLE IF NOT EXISTS chat_secret_recovery_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_owner INTEGER NOT NULL,
    owner_principal TEXT NOT NULL,
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 0),
    nonce BLOB NOT NULL UNIQUE CHECK(length(nonce) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_at INTEGER NOT NULL,
    last_error TEXT,
    done_at INTEGER,
    UNIQUE(storage_owner,owner_principal,first_principal,second_principal,version)
);

CREATE TABLE IF NOT EXISTS chat_secret_rejected_proposals (
    signer TEXT NOT NULL,
    message_id TEXT NOT NULL,
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    operation_digest BLOB NOT NULL CHECK(length(operation_digest)=32),
    rejected_at INTEGER NOT NULL,
    PRIMARY KEY(signer,message_id)
);

CREATE TABLE IF NOT EXISTS chat_secrets (
                user_id TEXT NOT NULL, chat_id TEXT NOT NULL, secret_id TEXT NOT NULL,
                version INTEGER NOT NULL, encrypted_secret BLOB NOT NULL,
                kem_ciphertext BLOB NOT NULL, wrapping_scheme TEXT NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, chat_id, secret_id, version)
             );

CREATE TABLE IF NOT EXISTS client_device_sync_state (
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                acknowledged_version INTEGER NOT NULL,
                cache_schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, device_id)
            );

CREATE TABLE IF NOT EXISTS client_message_deliveries (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                sync_version INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id, sync_version, message_id)
            );

CREATE TABLE IF NOT EXISTS client_sync_state (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                acknowledged_version INTEGER NOT NULL,
                cache_schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, session_id)
            );

CREATE TABLE IF NOT EXISTS communities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                address TEXT NOT NULL,
                title TEXT NOT NULL,
                position TEXT NOT NULL,
                UNIQUE(storage_owner, address)
            );

CREATE TABLE IF NOT EXISTS "contacts" (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    storage_owner INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    principal_handle INTEGER REFERENCES principals(principal_pk),
                    user_name TEXT,
                    created_at INTEGER NOT NULL,
                    last_message_at INTEGER,
                    notifications INTEGER NOT NULL DEFAULT 0,
                    notifications_read_at INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(storage_owner, principal_handle)
                );

CREATE TABLE IF NOT EXISTS federation_authorities (
    authority_id TEXT NOT NULL,
    locator TEXT NOT NULL UNIQUE,
    node_id TEXT,
    discovered_at INTEGER NOT NULL,
    verified_at INTEGER NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('https_domain','explicit_pin','manual')),
    is_preferred INTEGER NOT NULL DEFAULT 0 CHECK(is_preferred IN (0,1)),
    PRIMARY KEY(authority_id, locator)
);

CREATE TABLE IF NOT EXISTS federation_peer_admissions (
    node_id TEXT PRIMARY KEY, auth_hint INTEGER NOT NULL, public_key TEXT NOT NULL,
    descriptor TEXT NOT NULL, admitted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('provisional','established','revoked')),
    descriptor_rev INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS federation_peer_challenges (
    challenge_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, descriptor_hash BLOB NOT NULL,
    nonce TEXT NOT NULL, responder_node TEXT NOT NULL, origin TEXT NOT NULL, authority_locator TEXT,
    expires_at INTEGER NOT NULL, consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS file_changes (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            kind TEXT NOT NULL, payload TEXT NOT NULL
        );

CREATE TABLE IF NOT EXISTS file_folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            folder_id TEXT NOT NULL, parent_folder_id TEXT NOT NULL,
            revision INTEGER NOT NULL, payload TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
            UNIQUE(storage_user_id,folder_id)
        );

CREATE TABLE IF NOT EXISTS file_managed_assets (
            storage_user_id INTEGER NOT NULL, asset_id TEXT NOT NULL,
            released_at INTEGER,
            PRIMARY KEY(storage_user_id,asset_id)
        );

CREATE TABLE IF NOT EXISTS file_placements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            placement_id TEXT NOT NULL, origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL,
            folder_id TEXT NOT NULL, revision INTEGER NOT NULL, payload TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            UNIQUE(storage_user_id,placement_id)
        );

CREATE TABLE IF NOT EXISTS file_replication_jobs (
            version_id INTEGER PRIMARY KEY, upload_id TEXT NOT NULL, asset_id TEXT NOT NULL,
            next_attempt_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        );

CREATE TABLE IF NOT EXISTS file_share_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT, storage_user_id INTEGER NOT NULL,
            origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL, version INTEGER NOT NULL,
            recipient_principal INTEGER NOT NULL, chat_id TEXT NOT NULL, revision INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('offered','accepted','revoked','rejected')),
            expires_at INTEGER NOT NULL, manifest TEXT, source_node TEXT,
            proof TEXT,
            UNIQUE(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id)
        );

CREATE TABLE IF NOT EXISTS file_tombstones (
            storage_user_id INTEGER NOT NULL, origin_principal INTEGER NOT NULL, file_id TEXT NOT NULL,
            PRIMARY KEY(storage_user_id,origin_principal,file_id)
        );

CREATE TABLE IF NOT EXISTS file_transfer_usage (
            storage_user_id INTEGER NOT NULL, recipient_principal INTEGER NOT NULL,
            day INTEGER NOT NULL, bytes INTEGER NOT NULL,
            PRIMARY KEY(storage_user_id,recipient_principal)
        );

CREATE TABLE IF NOT EXISTS file_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storage_user_id INTEGER NOT NULL,
            origin_principal INTEGER NOT NULL,
            file_id TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            manifest TEXT NOT NULL,
            metadata_revision INTEGER NOT NULL DEFAULT 1,
            asset_id TEXT,
            state TEXT NOT NULL CHECK(state IN ('pending','transferring','ready','failed','deleted')),
            UNIQUE(storage_user_id,origin_principal,file_id,version)
        );

CREATE TABLE IF NOT EXISTS hosted_auth_changes (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), sequence INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS hosted_auth_state (
            local_user_id INTEGER PRIMARY KEY,
            generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation > 0),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
        );

CREATE TABLE IF NOT EXISTS hosted_connection_authorizations (
            connection_id TEXT PRIMARY KEY,
            server_instance TEXT NOT NULL,
            local_user_id INTEGER NOT NULL,
            principal_handle INTEGER NOT NULL,
            auth_generation INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
        );

CREATE TABLE IF NOT EXISTS hosted_forwarded_revocations (
    connection_id TEXT PRIMARY KEY NOT NULL,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosted_principals (
                local_user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                principal_handle INTEGER NOT NULL UNIQUE REFERENCES principals(principal_pk)
            );

CREATE TABLE IF NOT EXISTS hosted_server_instances (
            server_instance TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );

CREATE TABLE IF NOT EXISTS identity_configuration (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                omega_authority_id TEXT NOT NULL
            );

CREATE TABLE IF NOT EXISTS initial_secret_proposals (
    signer_principal TEXT NOT NULL,
    message_id TEXT NOT NULL CHECK(length(message_id) BETWEEN 1 AND 256),
    first_principal TEXT NOT NULL,
    second_principal TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version=1),
    operation_digest BLOB NOT NULL UNIQUE CHECK(length(operation_digest)=32),
    verified_prepared_operation BLOB NOT NULL CHECK(length(verified_prepared_operation) BETWEEN 1 AND 67108864),
    original_type_map_version TEXT NOT NULL,
    first_revision INTEGER NOT NULL,
    second_revision INTEGER NOT NULL,
    first_home TEXT NOT NULL,
    second_home TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('awaiting_peer_proof','verifying','committed','rejected')),
    attempt_generation INTEGER NOT NULL DEFAULT 0 CHECK(attempt_generation>=0),
    claim_owner TEXT,
    claim_deadline INTEGER,
    next_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_error TEXT,
    PRIMARY KEY(signer_principal,message_id)
);

CREATE TABLE IF NOT EXISTS local_identity_allocator (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_user_id INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS message_edits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL REFERENCES messages(id),
                content_before TEXT NOT NULL,
                content_after TEXT NOT NULL,
                edited_at INTEGER NOT NULL,
                edited_by INTEGER NOT NULL
            , content_before_key_version INTEGER CHECK(content_before_key_version > 0), content_after_key_version INTEGER CHECK(content_after_key_version > 0));

CREATE TABLE IF NOT EXISTS message_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    storage_owner INTEGER NOT NULL,
                    target_signer_id INTEGER NOT NULL,
                    target_signer_principal INTEGER REFERENCES principals(principal_pk),
                    target_message_id TEXT NOT NULL,
                    receipt_signer_id INTEGER NOT NULL,
                    receipt_signer_principal INTEGER REFERENCES principals(principal_pk),
                    receipt_message_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL CHECK (receipt_type IN ('received', 'read')),
                    event_at INTEGER NOT NULL,
                    recorded_at INTEGER NOT NULL
                );

CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_owner INTEGER NOT NULL,
                external_user INTEGER NOT NULL,
                message_time INTEGER NOT NULL,
                content TEXT NOT NULL,
                sent_by_self INTEGER NOT NULL,
                message_state TEXT NOT NULL,
                delivery_pruned INTEGER NOT NULL DEFAULT 0 CHECK (delivery_pruned IN (0, 1))
            , height INTEGER NOT NULL DEFAULT 0, reply_to INTEGER, edited_count INTEGER NOT NULL DEFAULT 0, deleted_by_external INTEGER NOT NULL DEFAULT 0, key_version INTEGER NOT NULL DEFAULT 1, relay_signer_id INTEGER, relay_message_id TEXT, authored_at INTEGER, origin_iota_received_at INTEGER, destination_iota_received_at INTEGER, client_received_at INTEGER, client_received_recorded_at INTEGER, read_at INTEGER, read_recorded_at INTEGER, delivery_failed_at INTEGER, delivery_failure TEXT, stored_at INTEGER, expires_at INTEGER, history_deleted INTEGER NOT NULL DEFAULT 0 CHECK (history_deleted IN (0, 1)), history_deleted_at INTEGER, external_principal INTEGER REFERENCES principals(principal_pk), relay_signer_principal INTEGER REFERENCES principals(principal_pk));

CREATE TABLE IF NOT EXISTS node_directory (
                node_id TEXT PRIMARY KEY,
                descriptor_revision INTEGER NOT NULL,
                descriptor_valid_until INTEGER,
                direct_endpoints TEXT NOT NULL,
                relay_hints TEXT NOT NULL,
                last_successful_endpoint TEXT,
                last_resolved_at INTEGER NOT NULL
            , authentication_hint INTEGER);

CREATE TABLE IF NOT EXISTS node_endpoint_pins (
                endpoint TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                pinned_at INTEGER NOT NULL
            , tls_certificate BLOB);

CREATE TABLE IF NOT EXISTS node_keys (
                node_id TEXT NOT NULL REFERENCES node_directory(node_id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                valid_from INTEGER NOT NULL,
                valid_until INTEGER,
                source_revision INTEGER NOT NULL,
                PRIMARY KEY (node_id, public_key)
            );

CREATE TABLE IF NOT EXISTS node_transitions (
    previous_node TEXT PRIMARY KEY, replacement_node TEXT NOT NULL,
    previous_descriptor_revision INTEGER NOT NULL, effective_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, proof TEXT NOT NULL, accepted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_relays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                destination_id INTEGER NOT NULL,
                target_kind INTEGER NOT NULL DEFAULT 0,
                frame BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                frame_id INTEGER NOT NULL DEFAULT 0, type_map_version TEXT NOT NULL DEFAULT '1.0', relay_signer_id INTEGER, relay_destination_user_id INTEGER, relay_message_id TEXT, delivery_state TEXT NOT NULL DEFAULT 'ready' CHECK (delivery_state IN ('ready', 'waiting_client', 'quarantined')), last_error TEXT, destination_principal INTEGER REFERENCES principals(principal_pk), signer_principal INTEGER REFERENCES principals(principal_pk), destination_node_id TEXT, destination_authority_id TEXT, attempt_count INTEGER NOT NULL DEFAULT 0, last_attempt_at INTEGER, next_attempt_at INTEGER NOT NULL DEFAULT 0, dispatch_generation INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_generation >= 0), dispatch_owner TEXT, dispatch_deadline INTEGER,
                UNIQUE(destination_id, frame)
            );

CREATE TABLE IF NOT EXISTS pending_user_operations (
                    user_id INTEGER PRIMARY KEY,
                    operation TEXT NOT NULL
                        CHECK (operation IN ('create', 'attach', 'release', 'purge')),
                    username TEXT NOT NULL,
                    public_key TEXT,
                    private_key_hash TEXT,
                    reset_token TEXT,
                    registration_token TEXT,
                    phase TEXT NOT NULL DEFAULT 'prepared'
                        CHECK (phase IN (
                            'prepared', 'credential_written', 'remote_committed', 'local_committed',
                            'database_purged', 'e2ee_purged', 'filesystem_purged'
                        )),
                    created_at INTEGER NOT NULL
                );

CREATE TABLE IF NOT EXISTS principal_keys (
                principal_pk INTEGER NOT NULL REFERENCES principals(principal_pk) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                valid_from INTEGER NOT NULL,
                valid_until INTEGER,
                source_revision INTEGER NOT NULL DEFAULT 0, key_id TEXT,
                PRIMARY KEY (principal_pk, public_key)
            );

CREATE TABLE IF NOT EXISTS principals (
                principal_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                authority_kind TEXT NOT NULL CHECK (authority_kind IN ('iota', 'omega')),
                authority_id TEXT NOT NULL,
                remote_user_id INTEGER NOT NULL,
                username TEXT,
                display_name TEXT,
                home TEXT,
                descriptor_revision INTEGER NOT NULL DEFAULT 0,
                descriptor_valid_until INTEGER,
                last_resolved_at INTEGER NOT NULL, retired_at INTEGER, descriptor_issued_at INTEGER,
                UNIQUE(authority_id, remote_user_id)
            );

CREATE TABLE IF NOT EXISTS protected_command_replay (
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_id, message_id)
            );

CREATE TABLE IF NOT EXISTS reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id INTEGER NOT NULL REFERENCES messages(id),
                    user_id INTEGER NOT NULL,
                    user_principal INTEGER REFERENCES principals(principal_pk),
                    reaction TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

CREATE TABLE IF NOT EXISTS relay_acceptance_receipts (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 storage_owner INTEGER NOT NULL,
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 accepted_at INTEGER NOT NULL,
 UNIQUE(storage_owner, signer_principal, message_id)
);

CREATE TABLE IF NOT EXISTS relay_deferred_secrets (
                 signer_principal INTEGER NOT NULL, message_id TEXT NOT NULL,
                 storage_owner INTEGER NOT NULL, owner_principal INTEGER NOT NULL,
                 legacy_chat_id TEXT, chat_id TEXT NOT NULL, secret_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0), encrypted_secret BLOB NOT NULL,
                 kem_ciphertext BLOB NOT NULL, wrapping_scheme TEXT NOT NULL,
                 created_at INTEGER NOT NULL, completed_at INTEGER,
                 PRIMARY KEY(signer_principal, message_id, storage_owner)
             );

CREATE TABLE IF NOT EXISTS "relay_inbox" (
                signer_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                destination_id INTEGER NOT NULL,
                frame BLOB NOT NULL,
                type_map_version TEXT NOT NULL,
                frame_id INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('received', 'processing', 'applied', 'queued', 'delivered', 'rejected')),
                accepted_at INTEGER,
                applied_at INTEGER,
                queued_at INTEGER,
                downstream_acked_at INTEGER,
                rejected_at INTEGER,
                processing_generation INTEGER NOT NULL DEFAULT 0 CHECK (processing_generation >= 0),
                processing_owner TEXT,
                processing_deadline INTEGER, prepared_operation BLOB, rejection_reason TEXT CHECK(rejection_reason IN ('unauthorized', 'invalid_operation')), recovery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(recovery_attempts >= 0), recovery_next_at INTEGER NOT NULL DEFAULT 0, recovery_status TEXT NOT NULL DEFAULT 'ready' CHECK(recovery_status IN ('ready', 'retry', 'blocked')), recovery_error_code TEXT, recovery_last_attempt_at INTEGER, initial_secret_ambiguous INTEGER NOT NULL DEFAULT 1, initial_secret_document TEXT GENERATED ALWAYS AS (
    CASE WHEN json_valid(CAST(prepared_operation AS TEXT)) THEN
        CASE WHEN json_type(CAST(prepared_operation AS TEXT),'$.schema_version') IS NULL
            THEN CAST(prepared_operation AS TEXT)
        WHEN json_extract(CAST(prepared_operation AS TEXT),'$.schema_version') IS '1'
            AND json_type(CAST(prepared_operation AS TEXT),'$.operation') = 'object'
            THEN json_extract(CAST(prepared_operation AS TEXT),'$.operation')
        END
    END
) VIRTUAL, initial_secret_chat_id TEXT GENERATED ALWAYS AS (
    CASE WHEN initial_secret_ambiguous != 0 OR initial_secret_document IS NULL THEN ''
        WHEN json_type(initial_secret_document,'$.operation.SetChatSecret') IS NOT NULL THEN
            CASE WHEN json_type(initial_secret_document,'$.operation.SetChatSecret.chat_id') = 'text'
                THEN json_extract(initial_secret_document,'$.operation.SetChatSecret.chat_id') ELSE '' END
        WHEN json_type(initial_secret_document,'$.operation.MessageSend') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageEdit') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReactionAdd') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReactionRemove') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageDelete') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageDeleteLive') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageState') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReceived') = 'object'
          OR json_type(initial_secret_document,'$.operation.AddConversation') = 'object'
            THEN NULL
        ELSE ''
    END
) VIRTUAL,
                CHECK ((state = 'processing' AND processing_owner IS NOT NULL AND processing_deadline IS NOT NULL)
                    OR (state <> 'processing' AND processing_owner IS NULL AND processing_deadline IS NULL)),
                PRIMARY KEY (signer_principal, message_id)
            );

CREATE TABLE IF NOT EXISTS relay_mailbox (
    destination_node TEXT NOT NULL, envelope_id BLOB NOT NULL, sender_node TEXT NOT NULL,
    encrypted_frame BLOB, frame_hash BLOB NOT NULL, type_map_version TEXT NOT NULL,
    stored_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    lease_owner BLOB, lease_until INTEGER, acceptance BLOB,
    PRIMARY KEY(destination_node,envelope_id)
);

CREATE TABLE IF NOT EXISTS relay_receipt_backfill_blocks (
 signer_principal INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 storage_owner INTEGER NOT NULL,
 reason TEXT NOT NULL,
 PRIMARY KEY(signer_principal, message_id, storage_owner)
);

CREATE TABLE IF NOT EXISTS "relay_replay" (
                signer_principal INTEGER NOT NULL REFERENCES principals(principal_pk),
                signer_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_principal, message_id)
            );

CREATE TABLE IF NOT EXISTS settings (
                user_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (user_id, session_id, name)
            );

CREATE TABLE IF NOT EXISTS sync_events (
                user_id INTEGER NOT NULL,
                version INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                operation TEXT NOT NULL,
                created_at INTEGER NOT NULL, projection BLOB, projection_principal TEXT, projection_generation INTEGER, projection_dictionary TEXT,
                PRIMARY KEY (user_id, version)
            );

CREATE TABLE IF NOT EXISTS sync_heads (
                user_id INTEGER PRIMARY KEY,
                version INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS synced_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scope_type TEXT NOT NULL
                    CHECK (scope_type IN ('user', 'contact', 'community')),
                scope_key TEXT NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                revision INTEGER NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0
                    CHECK (deleted IN (0, 1)),
                UNIQUE(user_id, scope_type, scope_key, name)
            );

CREATE TABLE IF NOT EXISTS tauth_codes (
                code_hash BLOB PRIMARY KEY,
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT NOT NULL,
                pkce_challenge TEXT NOT NULL,
                authorization_request TEXT NOT NULL,
                locator TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS tauth_grants (
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                app_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT NOT NULL,
                app_public_key TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                security_state TEXT NOT NULL CHECK (security_state IN ('secure', 'insecure')),
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (local_user_id, app_id)
            );

CREATE TABLE IF NOT EXISTS tauth_metadata (
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (local_user_id, app_id)
            );

CREATE TABLE IF NOT EXISTS tauth_owner_apps (
                app_id TEXT PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                public_key TEXT NOT NULL,
                owner_certificate TEXT NOT NULL,
                connection_mode TEXT NOT NULL CHECK (connection_mode IN ('hosted', 'forced_omikron')),
                endpoint_url TEXT NOT NULL,
                omikron_public_key TEXT,
                created_at INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS tauth_sessions (
                token_hash BLOB PRIMARY KEY,
                local_user_id INTEGER NOT NULL,
                app_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                locator TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS user_asset_uploads (
                upload_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                asset_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 BLOB NOT NULL,
                mime_type TEXT NOT NULL,
                received INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL CHECK (state IN ('uploading', 'committed')),
                revision INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                committed_at INTEGER
            );

CREATE TABLE IF NOT EXISTS user_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                asset_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 BLOB NOT NULL,
                mime_type TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                published_upload_id TEXT NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0,
                UNIQUE(user_id, asset_id)
            );

CREATE TABLE IF NOT EXISTS user_blobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                blob_id TEXT NOT NULL,
                blob BLOB NOT NULL,
                revision INTEGER NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, blob_id)
            );

CREATE TABLE IF NOT EXISTS user_invitations (
                invitation_id INTEGER NOT NULL,
                authority TEXT NOT NULL CHECK (authority IN ('omega', 'iota')),
                token_hash BLOB,
                label TEXT,
                password_protected INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                state TEXT NOT NULL CHECK (state IN ('pending', 'provisioning', 'redeemed', 'revoked', 'expired')),
                redeemed_user_id INTEGER,
                redeemed_at INTEGER,
                revoked_at INTEGER,
                pending_action TEXT CHECK (pending_action IS NULL OR pending_action = 'revoke'),
                pending_action_at INTEGER,
                remote_revision INTEGER NOT NULL DEFAULT 0,
                last_synced_at INTEGER,
                local_provisioned_user_id INTEGER,
                local_provisioned_at INTEGER,
                PRIMARY KEY (authority, invitation_id)
            );

CREATE TABLE IF NOT EXISTS user_message_storage_policy (
                user_id INTEGER PRIMARY KEY,
                history_mode TEXT NOT NULL CHECK (history_mode IN ('retain', 'delete_after_client_delivery')),
                retention_mode TEXT NOT NULL CHECK (retention_mode IN ('forever', 'duration')),
                retention_duration_ms INTEGER,
                revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS user_password_credentials (
                user_id INTEGER PRIMARY KEY,
                opaque_record BLOB NOT NULL,
                encrypted_tu_credential BLOB NOT NULL,
                account_public_key_sha256 BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            , opaque_profile INTEGER NOT NULL DEFAULT 1, setup_sha256 BLOB, password_principal TEXT, password_iota_id INTEGER);

CREATE TABLE IF NOT EXISTS user_password_mutations (
            user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            operation_id TEXT NOT NULL,
            request_sha256 BLOB NOT NULL CHECK(length(request_sha256) = 32),
            account_public_key TEXT NOT NULL,
            authorization_generation INTEGER NOT NULL,
            enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
            committed_at INTEGER NOT NULL,
            PRIMARY KEY(user_id, operation_id)
         );

CREATE TABLE IF NOT EXISTS user_receipt_policy (
                user_id INTEGER PRIMARY KEY,
                send_read_receipts INTEGER NOT NULL CHECK (send_read_receipts IN (0, 1)),
                send_received_receipts INTEGER NOT NULL CHECK (send_received_receipts IN (0, 1)),
                revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

CREATE TABLE IF NOT EXISTS user_residency (
                user_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('managed', 'released')),
                data_state TEXT NOT NULL CHECK (data_state IN ('present', 'empty')),
                updated_at INTEGER NOT NULL
            , credential_origin TEXT NOT NULL DEFAULT 'local' CHECK (credential_origin IN ('local', 'external')));

CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL,
                    private_key_hash TEXT,
                    reset_token TEXT,
                    created_at INTEGER NOT NULL,
                    display_name TEXT
                );

CREATE INDEX IF NOT EXISTS account_sync_pages_expiry ON account_sync_pages(expires_at);

CREATE INDEX IF NOT EXISTS call_envelopes_expiry ON call_envelopes (expires_at);

CREATE INDEX IF NOT EXISTS call_epoch_expiry ON call_epoch_envelopes(expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS chat_secret_escrows_operation ON chat_secret_escrows(signer,message_id);

CREATE INDEX IF NOT EXISTS chat_secret_outbox_owner_cursor ON chat_secret_outbox(storage_owner,owner_principal,id);

CREATE INDEX IF NOT EXISTS chat_secret_recovery_jobs_due ON chat_secret_recovery_jobs(done_at,next_at,id);

CREATE INDEX IF NOT EXISTS file_changes_owner ON file_changes(storage_user_id,sequence);

CREATE INDEX IF NOT EXISTS file_folder_parent ON file_folders(storage_user_id,parent_folder_id,deleted,id);

CREATE INDEX IF NOT EXISTS file_grant_chat ON file_share_grants(storage_user_id,chat_id,state,id);

CREATE INDEX IF NOT EXISTS file_placement_folder ON file_placements(storage_user_id,folder_id,deleted,id);

CREATE INDEX IF NOT EXISTS file_replication_schedule ON file_replication_jobs(next_attempt_at,version_id);

CREATE INDEX IF NOT EXISTS file_version_asset ON file_versions(storage_user_id,asset_id);

CREATE INDEX IF NOT EXISTS hosted_authorizations_owner
        ON hosted_connection_authorizations(local_user_id, revoked);

CREATE INDEX IF NOT EXISTS idx_blocked_users_owner ON blocked_users (user_id);

CREATE INDEX IF NOT EXISTS idx_chat_secrets_owner ON chat_secrets (user_id, chat_id, secret_id);

CREATE INDEX IF NOT EXISTS idx_client_message_deliveries_session
                ON client_message_deliveries (user_id, session_id, sync_version);

CREATE INDEX IF NOT EXISTS idx_communities_owner
                ON communities (storage_owner);

CREATE INDEX IF NOT EXISTS idx_contacts_owner
                    ON contacts (storage_owner, last_message_at DESC, user_id ASC);

CREATE INDEX IF NOT EXISTS idx_federation_authority_lookup
ON federation_authorities(authority_id, is_preferred DESC, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_mailbox_delivery ON relay_mailbox(destination_node,expires_at,stored_at);

CREATE INDEX IF NOT EXISTS idx_mailbox_sender ON relay_mailbox(sender_node,expires_at);

CREATE INDEX IF NOT EXISTS idx_message_edits_msg
                ON message_edits (message_id, edited_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_receipts_legacy_identity
                    ON message_receipts (
                        storage_owner, target_signer_id, target_message_id,
                        receipt_signer_id, receipt_type
                    )
                    WHERE target_signer_principal IS NULL
                      AND receipt_signer_principal IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_receipts_legacy_message
                    ON message_receipts (receipt_signer_id, receipt_message_id)
                    WHERE receipt_signer_principal IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_receipts_principal_identity
                    ON message_receipts (
                        storage_owner, target_signer_principal, target_message_id,
                        receipt_signer_principal, receipt_type
                    )
                    WHERE target_signer_principal IS NOT NULL
                      AND receipt_signer_principal IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_receipts_principal_message
                    ON message_receipts (receipt_signer_principal, receipt_message_id)
                    WHERE receipt_signer_principal IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_message_receipts_principal_target
                    ON message_receipts (storage_owner, target_signer_principal, target_message_id);

CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages (storage_owner, expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_history_accepted
                    ON messages (
                        storage_owner,
                        external_user,
                        deleted_by_external,
                        destination_iota_received_at DESC,
                        origin_iota_received_at DESC,
                        authored_at DESC,
                        id DESC
                    );

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_legacy_relay_identity
                    ON messages (storage_owner, relay_signer_id, relay_message_id)
                    WHERE relay_signer_principal IS NULL AND relay_message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_lookup
                ON messages (storage_owner, external_user, message_time DESC);

CREATE INDEX IF NOT EXISTS idx_messages_principal_lookup ON messages (storage_owner, external_principal, message_time DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_relay_principal_identity
                    ON messages (storage_owner, relay_signer_principal, relay_message_id)
                    WHERE relay_signer_principal IS NOT NULL AND relay_message_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_node_authentication_hint ON node_directory(authentication_hint);

CREATE INDEX IF NOT EXISTS idx_node_keys_validity
                ON node_keys (node_id, valid_until);

CREATE INDEX IF NOT EXISTS idx_peer_admissions_hint ON federation_peer_admissions(auth_hint,expires_at);

CREATE INDEX IF NOT EXISTS idx_peer_challenge_expiry ON federation_peer_challenges(expires_at);

CREATE INDEX IF NOT EXISTS idx_peer_challenge_origin ON federation_peer_challenges(origin,expires_at);

CREATE INDEX IF NOT EXISTS idx_pending_relays_active
                    ON pending_relays (delivery_state, target_kind, destination_id, id);

CREATE INDEX IF NOT EXISTS idx_pending_relays_destination
                ON pending_relays (destination_id, id);

CREATE INDEX IF NOT EXISTS idx_pending_relays_dispatch ON pending_relays(delivery_state, next_attempt_at, dispatch_deadline, id);

CREATE INDEX IF NOT EXISTS idx_pending_user_operations_operation
                    ON pending_user_operations (operation, created_at);

CREATE INDEX IF NOT EXISTS idx_principal_keys_validity
                ON principal_keys (principal_pk, valid_until);

CREATE INDEX IF NOT EXISTS idx_principals_username
                ON principals (authority_id, username);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_legacy_identity
                    ON reactions (message_id, user_id, reaction)
                    WHERE user_principal IS NULL;

CREATE INDEX IF NOT EXISTS idx_reactions_msg
                    ON reactions (message_id, reaction);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_principal_identity
                    ON reactions (message_id, user_principal, reaction)
                    WHERE user_principal IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_relay_inbox_processing ON relay_inbox (processing_deadline)
                WHERE state = 'processing';

CREATE INDEX IF NOT EXISTS idx_relay_inbox_recovery ON relay_inbox(recovery_status, recovery_next_at, accepted_at) WHERE prepared_operation IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_relay_inbox_state ON relay_inbox (state, created_at);

CREATE INDEX IF NOT EXISTS idx_relay_replay_created_at ON relay_replay (created_at);

CREATE INDEX IF NOT EXISTS idx_settings_lookup
                ON settings (user_id, session_id, name);

CREATE INDEX IF NOT EXISTS idx_sync_events_user_version
                ON sync_events (user_id, version);

CREATE INDEX IF NOT EXISTS idx_synced_settings_owner
                ON synced_settings (user_id, deleted);

CREATE INDEX IF NOT EXISTS idx_synced_settings_scope
                ON synced_settings (user_id, scope_type, scope_key, deleted);

CREATE INDEX IF NOT EXISTS idx_user_blobs_owner
                ON user_blobs (user_id, deleted);

CREATE INDEX IF NOT EXISTS idx_user_invitations_state_created
                ON user_invitations (authority, state, created_at);

CREATE INDEX IF NOT EXISTS initial_secret_proposals_due ON initial_secret_proposals(state,next_at);

CREATE UNIQUE INDEX IF NOT EXISTS initial_secret_proposals_pair ON initial_secret_proposals(first_principal,second_principal,version)
    WHERE state IN ('awaiting_peer_proof','verifying');

CREATE INDEX IF NOT EXISTS principal_file_signing_key ON principal_keys(principal_pk,key_id);

CREATE INDEX IF NOT EXISTS protected_command_replay_created_at
                ON protected_command_replay (created_at);

CREATE INDEX IF NOT EXISTS relay_acceptance_receipts_owner_sequence
 ON relay_acceptance_receipts(storage_owner, sequence);

CREATE INDEX IF NOT EXISTS relay_inbox_initial_secret ON relay_inbox(signer_principal,initial_secret_chat_id)
WHERE prepared_operation IS NOT NULL AND state!='rejected';

CREATE INDEX IF NOT EXISTS relay_receipt_backfill_blocks_owner ON relay_receipt_backfill_blocks(storage_owner);

CREATE INDEX IF NOT EXISTS sync_snapshot_blocked_users ON blocked_users(user_id,id);

CREATE INDEX IF NOT EXISTS sync_snapshot_contacts ON contacts(storage_owner,id);

CREATE INDEX IF NOT EXISTS sync_snapshot_epochs_first ON chat_secret_epochs(first_principal);

CREATE INDEX IF NOT EXISTS sync_snapshot_epochs_second ON chat_secret_epochs(second_principal);

CREATE INDEX IF NOT EXISTS sync_snapshot_messages ON messages(storage_owner,id);

CREATE INDEX IF NOT EXISTS sync_snapshot_synced_settings ON synced_settings(user_id,id);

CREATE INDEX IF NOT EXISTS sync_snapshot_user_assets ON user_assets(user_id,id);

CREATE INDEX IF NOT EXISTS sync_snapshot_user_blobs ON user_blobs(user_id,id);

CREATE INDEX IF NOT EXISTS tauth_codes_expiry ON tauth_codes (expires_at);

CREATE INDEX IF NOT EXISTS tauth_sessions_grant ON tauth_sessions (local_user_id, app_id);

CREATE INDEX IF NOT EXISTS user_asset_uploads_owner ON user_asset_uploads (user_id, state, updated_at);

CREATE INDEX IF NOT EXISTS user_assets_owner ON user_assets (user_id, deleted);

CREATE TRIGGER IF NOT EXISTS account_sync_erasure AFTER DELETE ON hosted_auth_state BEGIN
            DELETE FROM account_sync_pages WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_checkpoints WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_floors WHERE user_id=OLD.local_user_id;
            DELETE FROM client_device_sync_state WHERE user_id=OLD.local_user_id;
         END;

CREATE TRIGGER IF NOT EXISTS account_sync_pages_delete AFTER DELETE ON account_sync_pages BEGIN
            DELETE FROM account_sync_page_items WHERE page_id=OLD.id;
         END;

CREATE TRIGGER IF NOT EXISTS account_sync_peer_erasure AFTER INSERT ON chat_secret_erasure_fences BEGIN
            DELETE FROM account_sync_pages;
         END;

CREATE TRIGGER IF NOT EXISTS account_sync_progress_delete AFTER DELETE ON account_sync_pages BEGIN
            DELETE FROM account_sync_page_progress WHERE page_id=OLD.id;
        END;

CREATE TRIGGER IF NOT EXISTS account_sync_revocation AFTER UPDATE ON hosted_auth_state
         WHEN NEW.generation != OLD.generation OR NEW.enabled=0 BEGIN
            DELETE FROM account_sync_pages WHERE user_id=OLD.local_user_id;
            DELETE FROM account_sync_checkpoints WHERE user_id=OLD.local_user_id;
            DELETE FROM client_device_sync_state WHERE user_id=OLD.local_user_id;
         END;

CREATE TRIGGER IF NOT EXISTS chat_secret_epochs_accepted_delete BEFORE DELETE ON chat_secret_epochs
WHEN OLD.state='committed' AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN (OLD.first_principal,OLD.second_principal))
BEGIN SELECT RAISE(ABORT, 'accepted chat secret epochs require an erasure fence'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_epochs_immutable BEFORE UPDATE ON chat_secret_epochs
WHEN NEW.first_principal != OLD.first_principal OR NEW.second_principal != OLD.second_principal
 OR NEW.version != OLD.version OR NEW.evidence_digest != OLD.evidence_digest OR OLD.state='committed'
BEGIN SELECT RAISE(ABORT, 'chat secret epoch is immutable'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_erasure_fences_delete BEFORE DELETE ON chat_secret_erasure_fences
BEGIN SELECT RAISE(ABORT, 'chat secret erasure is permanent'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_erasure_fences_update BEFORE UPDATE ON chat_secret_erasure_fences
BEGIN SELECT RAISE(ABORT, 'chat secret erasure is permanent'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_escrows_accepted_delete BEFORE DELETE ON chat_secret_escrows
WHEN OLD.state='committed' AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences WHERE principal IN (OLD.first_principal,OLD.second_principal))
BEGIN SELECT RAISE(ABORT, 'accepted chat secret evidence requires an erasure fence'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_escrows_immutable BEFORE UPDATE ON chat_secret_escrows
WHEN NEW.first_principal != OLD.first_principal OR NEW.second_principal != OLD.second_principal
 OR NEW.version != OLD.version OR NEW.evidence != OLD.evidence OR NEW.signer != OLD.signer
 OR NEW.message_id != OLD.message_id OR OLD.state = 'committed'
BEGIN SELECT RAISE(ABORT, 'chat secret evidence is immutable'); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_hosted_delete BEFORE DELETE ON hosted_principals BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=OLD.local_user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=OLD.local_user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=OLD.local_user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_hosted_reassign BEFORE UPDATE OF principal_handle,local_user_id ON hosted_principals WHEN OLD.principal_handle != NEW.principal_handle OR OLD.local_user_id != NEW.local_user_id BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=OLD.local_user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=OLD.local_user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=OLD.local_user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_outbox_insert AFTER INSERT ON chat_secret_outbox
BEGIN UPDATE chat_secret_changes SET sequence=sequence+1 WHERE singleton=1; END;

CREATE TRIGGER IF NOT EXISTS chat_secret_pending_purge AFTER INSERT ON pending_user_operations WHEN NEW.operation='purge' BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=NEW.user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=NEW.user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=NEW.user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_pending_purge_update AFTER UPDATE OF operation ON pending_user_operations WHEN NEW.operation='purge' BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=NEW.user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=NEW.user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=NEW.user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_residency_erasure BEFORE UPDATE ON user_residency WHEN NEW.data_state='empty' BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=OLD.user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=OLD.user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=OLD.user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_sync_insert AFTER INSERT ON chat_secrets BEGIN
            INSERT INTO sync_heads(user_id,version) VALUES(CAST(NEW.user_id AS INTEGER),1)
            ON CONFLICT(user_id) DO UPDATE SET version=version+1;
            INSERT INTO sync_events(user_id,version,entity_type,entity_id,operation,created_at)
            SELECT user_id,version,'chat_secret',NEW.rowid,'upsert',NEW.updated_at FROM sync_heads WHERE user_id=CAST(NEW.user_id AS INTEGER);
         END;

CREATE TRIGGER IF NOT EXISTS chat_secret_user_delete BEFORE DELETE ON users BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=OLD.user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=OLD.user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=OLD.user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS chat_secret_user_rekey BEFORE UPDATE OF public_key ON users WHEN OLD.public_key != NEW.public_key BEGIN INSERT INTO chat_secret_erasure_fences(principal,erased_at)
            SELECT json_object('authority',p.authority_id,'user_id',p.remote_user_id),0 FROM hosted_principals h JOIN principals p ON p.principal_pk=h.principal_handle WHERE h.local_user_id=OLD.user_id
            AND NOT EXISTS(SELECT 1 FROM chat_secret_erasure_fences f WHERE f.principal=json_object('authority',p.authority_id,'user_id',p.remote_user_id));
            DELETE FROM chat_secret_escrows WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_epochs WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_rejected_proposals WHERE first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_recovery_jobs WHERE storage_owner=OLD.user_id OR first_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR second_principal IN (SELECT principal FROM chat_secret_erasure_fences);
            DELETE FROM chat_secret_outbox WHERE storage_owner=OLD.user_id OR owner_principal IN (SELECT principal FROM chat_secret_erasure_fences) OR peer_principal IN (SELECT principal FROM chat_secret_erasure_fences); END;

CREATE TRIGGER IF NOT EXISTS contacts_assign_principal_after_insert
                AFTER INSERT ON contacts
                WHEN NEW.principal_handle IS NULL
                BEGIN
                    INSERT OR IGNORE INTO principals (
                        authority_kind, authority_id, remote_user_id,
                        descriptor_revision, last_resolved_at
                    )
                    SELECT 'omega', omega_authority_id, NEW.user_id, 0, 0
                    FROM identity_configuration
                    WHERE singleton = 1 AND NEW.user_id > 0;
                    UPDATE contacts
                    SET principal_handle = (
                        SELECT p.principal_pk
                        FROM principals p
                        JOIN identity_configuration c
                          ON c.singleton = 1 AND p.authority_id = c.omega_authority_id
                        WHERE p.remote_user_id = NEW.user_id
                    )
                    WHERE rowid = NEW.rowid;
                END;

CREATE TRIGGER IF NOT EXISTS file_asset_immutable BEFORE UPDATE ON user_assets
        WHEN EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=OLD.user_id AND v.asset_id=OLD.asset_id)
          AND (NEW.file_name!=OLD.file_name OR NEW.sha256!=OLD.sha256 OR NEW.size!=OLD.size OR NEW.deleted!=OLD.deleted)
        BEGIN SELECT RAISE(ABORT,'file version asset is immutable'); END;

CREATE TRIGGER IF NOT EXISTS file_asset_pinned BEFORE DELETE ON user_assets
        WHEN EXISTS(SELECT 1 FROM file_versions v WHERE v.storage_user_id=OLD.user_id AND v.asset_id=OLD.asset_id)
        BEGIN SELECT RAISE(ABORT,'file version asset is referenced'); END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_authority AFTER UPDATE OF authority_kind, authority_id, remote_user_id, home, retired_at ON principals
        WHEN NEW.authority_kind IS NOT OLD.authority_kind OR NEW.authority_id IS NOT OLD.authority_id
          OR NEW.remote_user_id IS NOT OLD.remote_user_id OR NEW.home IS NOT OLD.home
          OR NEW.retired_at IS NOT OLD.retired_at
        BEGIN
            UPDATE hosted_auth_state SET generation = generation + 1,
                enabled = CASE WHEN NEW.retired_at IS NULL THEN enabled ELSE 0 END
            WHERE local_user_id IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = OLD.principal_pk);
        END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_bind AFTER INSERT ON hosted_principals WHEN 1 BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = NEW.local_user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = enabled
                WHERE local_user_id = NEW.local_user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_binding AFTER UPDATE ON hosted_principals WHEN NEW.principal_handle != OLD.principal_handle OR NEW.local_user_id != OLD.local_user_id BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = OLD.local_user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = enabled
                WHERE local_user_id = OLD.local_user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_create AFTER INSERT ON users
             BEGIN
                 INSERT INTO hosted_auth_state VALUES (NEW.user_id, 1, 1)
                 ON CONFLICT(local_user_id) DO UPDATE SET generation = generation + 1, enabled = 1;
             END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_delete BEFORE DELETE ON users WHEN 1 BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = OLD.user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = 0
                WHERE local_user_id = OLD.user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_invalidate AFTER UPDATE ON hosted_auth_state
        BEGIN UPDATE hosted_connection_authorizations SET revoked = 1
              WHERE local_user_id = NEW.local_user_id;
              UPDATE hosted_auth_changes SET sequence = sequence + 1 WHERE singleton = 1; END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_key AFTER UPDATE OF public_key ON users WHEN NEW.public_key != OLD.public_key BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = NEW.user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = enabled
                WHERE local_user_id = NEW.user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_monotonic BEFORE UPDATE ON hosted_auth_state
        BEGIN
            SELECT CASE WHEN OLD.generation = 9223372036854775807
                THEN RAISE(ABORT, 'hosted auth generation exhausted') END;
            SELECT CASE WHEN NEW.generation <= OLD.generation
                THEN RAISE(ABORT, 'hosted auth generation must increase') END;
        END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_moved_binding AFTER UPDATE ON hosted_principals WHEN NEW.local_user_id != OLD.local_user_id BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = NEW.local_user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = enabled
                WHERE local_user_id = NEW.local_user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_principal_delete BEFORE DELETE ON principals BEGIN
            UPDATE hosted_auth_state SET generation = generation + 1, enabled = 0
            WHERE local_user_id IN (SELECT local_user_id FROM hosted_principals WHERE principal_handle = OLD.principal_pk);
        END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_released_residency AFTER INSERT ON user_residency WHEN NEW.lifecycle_state = 'released' BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = NEW.user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = 0
                WHERE local_user_id = NEW.user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_residency AFTER UPDATE OF lifecycle_state ON user_residency WHEN NEW.lifecycle_state != OLD.lifecycle_state BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = NEW.user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = CASE WHEN NEW.lifecycle_state = 'managed' THEN 1 ELSE 0 END
                WHERE local_user_id = NEW.user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_tombstone BEFORE DELETE ON hosted_auth_state
        BEGIN SELECT RAISE(ABORT, 'hosted auth tombstones must survive deletion'); END;

CREATE TRIGGER IF NOT EXISTS hosted_auth_unbind BEFORE DELETE ON hosted_principals WHEN 1 BEGIN
                SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM hosted_auth_state WHERE local_user_id = OLD.local_user_id)
                    THEN RAISE(ABORT, 'missing hosted auth state') END;
                UPDATE hosted_auth_state SET generation = generation + 1, enabled = 0
                WHERE local_user_id = OLD.local_user_id;
            END;

CREATE TRIGGER IF NOT EXISTS hosted_forwarded_revocations_delete BEFORE DELETE ON hosted_forwarded_revocations
BEGIN SELECT RAISE(ABORT,'forwarded cancellation is permanent'); END;

CREATE TRIGGER IF NOT EXISTS hosted_forwarded_revocations_immutable BEFORE UPDATE ON hosted_forwarded_revocations
BEGIN SELECT RAISE(ABORT,'forwarded cancellation is permanent'); END;

CREATE TRIGGER IF NOT EXISTS hosted_server_expiry BEFORE INSERT ON hosted_connection_authorizations
        WHEN NOT EXISTS (SELECT 1 FROM hosted_server_instances
            WHERE server_instance = NEW.server_instance AND expires_at > unixepoch())
        BEGIN SELECT RAISE(ABORT, 'hosted server lease expired'); END;

CREATE TRIGGER IF NOT EXISTS initial_secret_proposals_erasure AFTER INSERT ON chat_secret_erasure_fences
BEGIN DELETE FROM initial_secret_proposals WHERE first_principal=NEW.principal OR second_principal=NEW.principal; END;

CREATE TRIGGER IF NOT EXISTS initial_secret_proposals_immutable BEFORE UPDATE ON initial_secret_proposals
WHEN NEW.signer_principal!=OLD.signer_principal OR NEW.message_id!=OLD.message_id
    OR NEW.first_principal!=OLD.first_principal OR NEW.second_principal!=OLD.second_principal
    OR NEW.version!=OLD.version OR NEW.operation_digest!=OLD.operation_digest
    OR NEW.verified_prepared_operation!=OLD.verified_prepared_operation
    OR NEW.original_type_map_version!=OLD.original_type_map_version
    OR NEW.first_revision!=OLD.first_revision OR NEW.second_revision!=OLD.second_revision
    OR NEW.first_home!=OLD.first_home OR NEW.second_home!=OLD.second_home
    OR NEW.created_at!=OLD.created_at OR OLD.state IN ('committed','rejected')
BEGIN SELECT RAISE(ABORT,'initial secret proposal is immutable'); END;

CREATE TRIGGER IF NOT EXISTS messages_assign_principal_after_insert AFTER INSERT ON messages WHEN NEW.external_principal IS NULL BEGIN INSERT OR IGNORE INTO principals (authority_kind, authority_id, remote_user_id, descriptor_revision, last_resolved_at) SELECT 'omega', omega_authority_id, NEW.external_user, 0, 0 FROM identity_configuration WHERE singleton = 1 AND NEW.external_user > 0; UPDATE messages SET external_principal = (SELECT p.principal_pk FROM principals p JOIN identity_configuration c ON c.singleton = 1 AND p.authority_id = c.omega_authority_id WHERE p.remote_user_id = NEW.external_user) WHERE rowid = NEW.rowid; END;

CREATE TRIGGER IF NOT EXISTS relay_inbox_initial_secret_insert AFTER INSERT ON relay_inbox
BEGIN
    UPDATE relay_inbox SET initial_secret_ambiguous = CASE
        WHEN json_valid(CAST(NEW.prepared_operation AS TEXT)) THEN EXISTS (
            SELECT 1 FROM json_tree(CAST(NEW.prepared_operation AS TEXT))
            WHERE typeof(key)='text' GROUP BY parent,key HAVING COUNT(*)>1
        ) ELSE 1 END
    WHERE rowid=NEW.rowid;
END;

CREATE TRIGGER IF NOT EXISTS relay_inbox_initial_secret_update AFTER UPDATE OF prepared_operation ON relay_inbox
BEGIN
    UPDATE relay_inbox SET initial_secret_ambiguous = CASE
        WHEN json_valid(CAST(NEW.prepared_operation AS TEXT)) THEN EXISTS (
            SELECT 1 FROM json_tree(CAST(NEW.prepared_operation AS TEXT))
            WHERE typeof(key)='text' GROUP BY parent,key HAVING COUNT(*)>1
        ) ELSE 1 END
    WHERE rowid=NEW.rowid;
END;

CREATE TRIGGER IF NOT EXISTS sync_event_projection_immutable BEFORE UPDATE ON sync_events
             WHEN OLD.projection IS NOT NULL OR OLD.projection_principal IS NOT NULL
               OR OLD.projection_generation IS NOT NULL OR OLD.projection_dictionary IS NOT NULL
             BEGIN SELECT RAISE(ABORT,'sync event is immutable'); END;

CREATE TRIGGER IF NOT EXISTS user_password_mutations_immutable BEFORE UPDATE ON user_password_mutations
         BEGIN SELECT RAISE(ABORT, 'password mutation receipts are immutable'); END;

CREATE TRIGGER IF NOT EXISTS user_password_mutations_key_change AFTER UPDATE OF public_key ON users
         WHEN OLD.public_key != NEW.public_key
         BEGIN DELETE FROM user_password_mutations WHERE user_id = NEW.user_id; END;

CREATE TRIGGER IF NOT EXISTS user_password_mutations_residency AFTER UPDATE ON user_residency
         WHEN NEW.lifecycle_state != 'managed' OR NEW.data_state != 'present'
         BEGIN DELETE FROM user_password_mutations WHERE user_id = NEW.user_id; END;

INSERT OR IGNORE INTO hosted_auth_changes VALUES(1,0);
INSERT OR IGNORE INTO chat_secret_changes VALUES(1,0);
INSERT OR IGNORE INTO local_identity_allocator VALUES(1,1);
