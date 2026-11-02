# File sharing backend API

The backend stores opaque ciphertext and wrapped keys. Nothing in the top-level
`client/` has changed. Shared wire structures are in
`tau/relay-protocol/src/files.rs`; use those definitions as the API contract.

## Connection and wire format

Build the browser SDK with the updated `mtp-type-maps/type-maps.yaml` and select
dictionary **1.1**. Dictionary 1.0 is retained unchanged for old clients and queued
relays. Iota and Omikron pin the published Tau and type-map revisions in Cargo and
Nix; sibling checkout overrides are no longer required. Publish and pin an updated
browser SDK before enabling this in the client. Omikron forwards file operations
only to the authenticated user's hosting Iota. The development shells use the
checked-in maps through `.cargo/config.toml`.

Local requests go to the user's authenticated Iota. Their sender is replaced by
the hosted account identity. Each file operation carries a single `Json` **string**
containing the corresponding Rust structure. Responses use the same message type,
correlation ID and a `Json` string. Byte fields inside JSON are arrays of integers.
Times are Unix milliseconds. Preserve integer IDs exactly when parsing JSON.

| MTP operation | JSON body | Result |
| --- | --- | --- |
| `FileFolderPut` | `Folder` | Create, rename or move a private folder |
| `FileFolderDelete` | `DeleteEntry` | Delete an empty private folder |
| `FilePlacementPut` | `Placement` | Create/move a private placement or hide a chat entry locally |
| `FilePlacementDelete` | `DeleteEntry` | Remove only a local placement |
| `FileVersionPublish` | `PublishVersion` | Associate verified committed ciphertext with an immutable version |
| `FileUploadStart` | `FileUploadStart` | Reserve a file upload and register orphan cleanup intent |
| `FileKeyEnvelopePut` | `RewrapKey` | Replace this account's envelope using `expected_key_id` |
| `FileMetadataPut` | `MetadataUpdate` | Rename/update an authored version's encrypted manifest using `expected_revision` |
| `FileGetManifest` | `FileKey` | Manifest, account-local asset ID, state and transfer progress |
| `FileListPage` | `ListPage` | `items`, `next`; null means complete |
| `FileChangesGet` | `ChangesPage` | Durable file journal with `events`, `next`, `upper`, `more` |
| `FileReplicaAccept` | `FileKey` | Reserve quota and schedule a mirror; repeat to restart a failed transfer |
| `FileReplicaCancel` | `FileKey` | Reject/cancel and release the local mirror |
| `FileReplicaStatus` | `FileKey` | Same result as `FileGetManifest` |
| `FileDelete` | `{"file_id":"…"}` | Delete an authored file after revoking its active shares |

Folder and placement revisions start at 1 and increment by one. Exact retries are
idempotent; conflicting updates return `file_invalid_or_conflict`. IDs use 1 to 128
ASCII letters, digits, underscores or hyphens. Generate random IDs, not filenames.
The private root is `private`; a chat root is `chat:<canonical chat ID>`.

## Upload privately

1. Generate a fresh 32-byte DEK per content version. Encrypt chunks and the
   shareable manifest locally, then wrap the DEK for the owner's verified key.
   See [file crypto v1](../tau/file-crypto-v1.md). Never send a plaintext DEK,
   filename, MIME type, digest or private path to Iota.
2. Stage ciphertext and its SHA-256 locally. Upload with existing
   `FileUploadStart`, using a fresh asset ID; it fixes MIME to
   `application/octet-stream` and registers lifecycle intent. Continue with existing
   `UserAssetUploadChunk/Status/Commit/Abort`. Resume from the acknowledged offset.
   Retry logical publication after a lost reply; committed unpublished file intents
   are collected after a day without references. Legacy `UserAssetUploadStart`
   still works, but cannot distinguish unpublished files from background assets.
3. Call `FileVersionPublish` with `expected_predecessor: 0`, version 1, the asset
   ID and the owner-addressed manifest. Later versions use a new DEK and asset ID,
   with the previous version as `expected_predecessor`.
4. Create a separate `Placement` in `private` or a private folder. Folder names
   and placement `encrypted_metadata` use an account-only metadata key with AAD
   bound to IDs, parent and revision. Never put a private path in the file manifest.

Read with `FileGetManifest`, unwrap locally, then use owner-scoped
`UserAssetGetChunk` against the returned asset ID. Verify the ciphertext hash,
manifest and chunk authentication before exporting plaintext. Keep buffers bounded.
The old chat-background format is unchanged.

## Share and revoke

Unwrap the existing DEK locally and wrap it for the verified recipient. Send
`FileShareOffered` through the existing **signed, sealed durable Relay** path.
Its inner `Json` string is a `ShareOffer`: recipient-addressed manifest, canonical
`chat_id`, positive `grant_revision`, `expires_at`, `signing_public_key` and
`signature`. Sign `ShareOffer::signing_bytes()` with the user's MTP dual signer.
The public key is the base64 MTP bundle; signature bytes concatenate Ed25519 and
ML-DSA-65 signatures. Both must match the verified Relay signer. The ciphertext descriptor
must match the published version. No ciphertext upload or re-encryption occurs.

Derive chat IDs with `tau::relay_protocol::canonical_chat_id`, using both authority
and user ID. Never sort numeric IDs yourself. The server derives the source Iota
from the verified signer, not a client-supplied URL.

The recipient sees `pending`, then explicitly calls `FileReplicaAccept`.
The Iota reserves its normal asset quota, transfers bounded ranges, resumes after
restart, verifies SHA-256 and marks the mirror `ready`. The originating browser
may disconnect. Poll status for `transfer.offset`, `attempts`, `error`,
`next_attempt_at`, and account `reserved_bytes`. Cancellation is local, not a
revocation of the author's file. Reaccepting a rejected offer is supported.

Send owner-signed `FileShareRevoked` through Relay with `ShareRevoke` and a higher
revision to revoke **that version's** grant. Include its exact `recipient` and sign
`ShareRevoke::signing_bytes()` the same way. Use the `shares` list to revoke every
version/recipient before `FileDelete`. Renewal or recipient key rotation uses a
new offer with a higher revision and unchanged ciphertext. Grant expiry is an
actual access deadline; choose it deliberately and renew before it expires.
Revocation cannot erase keys or plaintext already copied by a recipient.

For rename without content re-encryption, encrypt a new manifest with a fresh
nonce, call `FileMetadataPut` using `metadata_revision` from `FileGetManifest`,
then send higher-revision offers to active recipients to propagate the new name.
Chunk layout and content AAD must stay unchanged.

## Listing and synchronization

`ListPage` has `namespace`, `folder_id`, `after: 0`, and optional `origin`.
Namespaces are `folders` and `private`, with the parent folder as `folder_id`;
`chat:<canonical chat ID>`, with any empty `folder_id`; and `versions` or `shares`,
with the file ID as `folder_id`. For the latter two, `origin` defaults to self.
Chat listings return one latest active version per author/file. Always fetch
`FileGetManifest` before opening, especially after local key rewrapping.
For a received file, verify its returned `proof` against the author's independently
authenticated key bundle and compare its signed descriptor with the manifest.
Do not trust a public key merely because an Iota included it in a response.
For local hiding, write a placement with that author/file, the chat root and
`hidden: true`. Deleting that placement unhides it. It never deletes the author.

For reliable multi-device initialization, replay `FileChangesGet` from
`{"after":0,"upper":null}`. Pin the returned `upper` while paging and persist
the returned `next`. Continue from there for live deltas. Apply events in order;
the file journal is separate from account-state snapshots. Bind cached cursors
to the canonical account and authorization generation. Tombstones are retained.

## Deployment and recovery limits

Binary mirroring supports same-Iota accounts and authenticated direct Iota peers.
Relay-only deployments deliver metadata but cannot proxy file bytes; accepted
transfers remain retryable until a direct route exists. Do not label them ready.
Canonical hosted identities and a running peer manager are required.
Peer reads use 256 KiB ranges and four concurrent read slots. The daily
author/recipient transfer allowance is four times the configured user asset quota.
Control events inherit the existing Relay retention window. After a peer exceeds
that window, convergence requires a fresh client-signed offer or revocation.
Mirrors lose access when grants expire, users block the author, or the Iota learns
that the author's canonical principal has retired. Offline/unreachable authors
alone do not trigger deletion. Re-downloads still require an available authorized
source. Account erasure removes local files and grants; it cannot erase plaintext
or independent copies already obtained by another account.

Iota startup backups now include referenced ciphertext and resumable staging files.
Storage also exports `db::backup_encrypted_storage` and
`db::restore_encrypted_storage`; restore creates a new directory and checks database
and committed-blob integrity. Back up server identity separately. These backups do
not recover lost client keys. Preserve the old key until envelope rewrapping has
finished, or provision the same recoverable account keyring to authorized devices.
Group ACLs, plaintext server WebDAV and mounted filesystems are not implemented.
