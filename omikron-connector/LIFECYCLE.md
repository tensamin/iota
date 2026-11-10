# Connector lifecycle

`stop()` returns `Result<ShutdownOutcome, ConnectorShutdownError>`. `Complete` means the
connection supervisor joined its attempt workers and handlers. `Incomplete`
means the five-second drain budget expired. The connector retains the supervisor
handle and its child tasks. Call `stop()` again to observe completion. Keep the
connector alive while draining. A worker panic produces an error rather than a
successful shutdown.

## Module and task hierarchy

`omikron_connection.rs` defines the public `OmikronConnection`, its shared state,
installation points and trait implementations. Its private modules add methods
to that same type. They do not own separate connection state or create another
relay recovery service.

| Module under `src/omikron_connection/` | Responsibility |
| --- | --- |
| `supervisor.rs` | Start, reconnect, attempt publication, bounded drain and joining retained attempts. |
| `workers.rs` | Attempt reader, handler admission and joins, ping/queue maintenance and invitation worker. |
| `discovery.rs` | Endpoint resolution and authenticated endpoint persistence. |
| `requests.rs` | Attempt-bound send and response correlation, connection waits. |
| `dispatch.rs` | Incoming frame validation and handler dispatch. |
| `relay.rs` | Relay ingress and exact-snapshot client delivery retries. |
| `invitations.rs` | Invitation snapshots and pending action synchronization. |
| `account.rs` | Account snapshots, receipt pages, provisioning and account cleanup. |
| `tauth_handlers.rs` | TAuth control handlers and signed locators. |
| `storage_handlers.rs` | Message reads, settings, assets and other shared storage handlers. |
| `diagnostics.rs` | Lifecycle event context and sticky worker failure reporting. |

```text
OmikronConnection
  connection_loop_handle, retained after an incomplete stop
    connection_loop
      discovery and authentication, cancelled before publication
      run_attempt
        reader
          handler JoinSet, joined without aborting mutations
          attempt-local preparation JoinSet, including blocking-worker wrappers
        invitation worker
        maintenance worker
      draining_attempts JoinSet
        old readers still joining handlers while a new attempt connects
  standalone preparation JoinSet
    adopted by a retained supervisor when stopped without a connection loop
```

Clones share connector state, cancellation, failure status and supervisor handles.
An attempt-bound clone changes only its bound transport and preparation task set.
Closing an old reader cannot clear a replacement attempt. The published attempt
comparison uses pointer identity before changing global connection state.

`Incomplete.pending_operations` is at least one while supervision remains
unfinished, even if no counted handler remains. It is not a count of durable queue
rows. Worker failure stays sticky after joining, so a later stop cannot turn an
unresolved panic into `Complete`.

Lifecycle diagnostics use component `omikron` and stable `connector.*` events.
Each event includes `connector`, `attempt` and `pending_operations`. State changes,
attempt publication/drain/closure, reconnect scheduling, request failures and drain
outcomes have distinct events. Worker failures identify the worker, Tokio task ID,
panic status and cancellation status without copying the panic payload. Generation
is `none` for connector-wide work or pre-publication discovery.

This join guarantee covers connector-owned tasks only. Pinned MTP revision
`ad48926` exposes transport closure but no join API for its private dispatcher,
ping, or transport tasks. `Sender::close()` only signals closure. The full
transport-child join requirement cannot be implemented in this crate while
MTP remains unchanged, so `Complete` does not prove those MTP tasks have joined.

Stopping disables reconnect, signals global cancellation, removes the published
attempt, closes its response correlator, and stops admission. The reader closes
the attempt transport and joins its handlers. Shutdown never aborts a mutation
handler. A disconnected attempt can drain under the connection supervisor while
a replacement connects. Every handler retains its originating attempt, so it
cannot send replies or register requests on the replacement transport.

## Work ownership

| Work | Shutdown behavior |
| --- | --- |
| Endpoint discovery and transport authentication | Cancel before attempt publication. |
| Relay signature and identity preparation | Cancel before calling `accept_verified_relay`. |
| Relay acceptance and committed mutation | Join the handler. The core persists the parsed operation and claim, and owns the fenced SQLite transaction. |
| Durable relay continuation | Leave persisted work for the process supervisor's recovery and dispatcher. Connector shutdown does not delete queue records. |
| TAuth and password identity HTTP discovery | Cancel before durable mutation. Password discovery bounds both response headers and body. |
| Account, invitation, metadata, and settings mutations | Run synchronous storage calls to completion. Any subsequent awaited work stays supervised. |
| Asset and password blocking workers | Await their blocking-task handle. Never cancel a handler around `spawn_blocking`. |
| Password KE1 delay | Cancel the delay. The attempt's preparation task set owns and joins the worker without occupying general handler capacity. |
| External account/control operations | Close their attempt correlator. An operation that does not return keeps shutdown incomplete and supervised. |
| Replies and local relay delivery attempts | Cancel on attempt closure. Durable local delivery records survive. |

The invitation worker is separate from ping and relay maintenance. Invitation
flush admission uses its existing atomic guard. Client relay flushes use a shared
mutex within one connector and storage-owned dispatch claims across independent
dispatchers. Neither worker overlaps flushes with handler-triggered flushes. Each
attempt owns and joins both workers.

`RelayReceiptPage` follows the authenticated Omikron account route, like
`AccountStateRequest`. The shared handler validates the sender and bounded page
parameters. Its response uses the originating attempt, and paging does not pause
or resume client relay delivery. The client's private-read final authorization
fence also covers receipt pages before sending account data to a client.

## Canonical relay delivery

The connector accepts signed relays using negotiated dictionaries and current
queue records.
It does not decode, backfill, or apply historical sealed relay content.

Install the process relay service with `install_relay_service`. Direct hosted
connections can be notified through `install_local_delivery_sink`. The bound
connector owns pending delivery through Omikron's `tensamin-hosted-delivery-v1`
envelope. Its context identifies the recipient, signer, canonical relay message
ID and stored dictionary version. The encrypted native frame remains opaque.
`install_pending_delivery_sink` replaces this transport only in lifecycle tests.

Omikron authorizes the recipient against the current Iota assignment and waits
for an acknowledgement on that recipient's client connection. Each transport
correlation ID is restored before returning upstream. Only `Status=notification`
with the matching signer and canonical relay ID retires the claimed notification.
Native relay IDs use `mtp-sealed-v1:<decimal u128>` in `RelayMessageId`.
Unsolicited successes, stale routes and offline responses leave queued work intact.

The connector lists recipient hints, then claims one due row with
`claim_ready_for_user` using the authenticated local user and principal. A listed
snapshot grants no network or mutation authority. The delivery transport uses the
claimed snapshot. The acknowledgement transaction checks the immutable snapshot,
`Ready` state and the current unexpired dispatch generation, owner and deadline
before it retires the notification and deletes the queue row. It does not delete
message history. Delivery waits end by the lease deadline. Failure scheduling and
quarantine use claim-qualified writes. A drop guard releases that exact claim on
cancellation, panic or an unmatched response.

Remote delivery belongs to the process supervisor. `OmikronPeerRouter` compares
the canonical route target with the V2 envelope's declared destination and sends
the frame unchanged. Numeric legacy relay routes are rejected. `ErrorInternal`
is retryable, and the process dispatcher validates the acceptance identity.
