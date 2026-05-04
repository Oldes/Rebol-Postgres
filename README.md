[![rebol-postgresql](https://github.com/user-attachments/assets/01be60b4-d2c3-4bb3-9718-11f4635a6209)](https://github.com/Oldes/Rebol-Postgres)

[![Rebol-Postgres CI](https://github.com/Oldes/Rebol-Postgres/actions/workflows/main.yml/badge.svg)](https://github.com/Oldes/Rebol-Postgres/actions/workflows/main.yml)
[![Gitter](https://badges.gitter.im/rebol3/community.svg)](https://gitter.im/rebol3/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Rebol/Postgres


[PostgreSQL](https://www.postgresql.org/) protocol scheme for [Rebol3](https://github.com/Siskin-framework/Rebol)

Current state of the scheme is under development and may be changed in any moment.

## Usage

Open a connection using the `postgres://` scheme.

```rebol
pgsql: import %postgres.reb

; user/pass are taken from the URL, database is taken from the URL path:
pg: open postgres://postgres:password@localhost/postgres

res: write pg "SELECT current_user, current_database();"
probe res/rows
probe res/columns
print res/command-tag

close pg
```

## Feature matrix (current)

| Area | Support | Notes |
|---|---|---|
| Authentication | SCRAM, MD5, cleartext | Controlled by `auth=scram,md5,cleartext` allowlist. Cleartext is insecure unless used over TLS. |
| TLS | `sslmode=disable|prefer|require` | `prefer` is downgradeable; use `require` on untrusted networks. No certificate verification knobs yet. |
| Query protocol | Simple Query + Extended Query | Extended Query block forms: `EXEC`, `PREPARE/EXECUTE/DEALLOCATE`, `CURSOR/FETCH/CLOSE-CURSOR`. |
| Results | rows + column metadata | `write` returns a `map!` with `rows`, `columns`, `command-tag`, `notices`, `runtime`, etc. |
| Row shaping | `row=flat|block|map` | `flat` is legacy flattened output; `block` nests per-row; `map` keys by column name. |
| Decoding | `decode=off|basic` (text format) | Basic scalar conversions (ints/bool/float/date). |
| Async | queued per-connection | `write` block forms: `ASYNC`, `ASYNC-STREAM` (rows streaming + optional chunking). |
| Notifications | LISTEN/NOTIFY | Handlers invoked from IO/awake context; keep handlers fast. |
| Cancel | CancelRequest | `pgsql/cancel pg` cancels current inflight query when `BackendKeyData` is available. |

### Connection options (query params)

You can pass a small set of options using URL query params:

- `database=<name>`: overrides the database from the URL path
- `auth=<list>`: comma-separated list of allowed authentication methods: `scram,md5,cleartext`
- `row=<mode>`: result row shaping: `flat` (default), `block`, `map`
- `decode=<mode>`: type decoding: `off` (default), `basic` (text format only)
- `application_name=<string>`: sets the Postgres `application_name` startup parameter
- `search_path=<string>`: runs `SET search_path TO ...` after connecting (treated as part of `open`)
  - Comma-separated schemas are supported (e.g. `public,extensions`)
  - `$user` is supported as a special token
- `connect-timeout=<seconds>`: handshake timeout (default: 10)
- `query-timeout=<seconds>`: timeout for blocking `write` (default: port spec `timeout`)
- `log=<int>`: sets `system/options/log/postgres` (scheme-wide)
- `trace=1|true|on`: more verbose protocol logging (auth payloads are still redacted)
- `sslmode=<mode>`: `disable` (default), `prefer`, `require`
  - `prefer` will try TLS and fall back to plaintext if the server refuses SSL.
  - `require` will error if the server refuses SSL.
  - `prefer` is vulnerable to downgrade (an active attacker can block SSLRequest); use `require` on untrusted networks.
  - Cleartext authentication over plaintext is insecure; use `sslmode=require` if you enable `auth=cleartext`.
  - Certificate verification knobs are not exposed by this scheme yet; treat TLS as encryption-in-transit, not identity verification.

Examples:

```rebol
; force database without changing the URL path
pg: open postgres://postgres:password@localhost?database=postgres

; allow only SCRAM (disable MD5 + cleartext)
pg: open postgres://postgres:password@localhost/postgres?auth=scram

; return rows as maps and decode basic scalar types
pg: open postgres://postgres:password@localhost/postgres?row=map&decode=basic

; require TLS (fails if server refuses SSL/TLS)
pg: open postgres://postgres:password@localhost/postgres?sslmode=require

; prefer TLS (use TLS if available, otherwise plaintext)
pg: open postgres://postgres:password@localhost/postgres?sslmode=prefer
```

### Error handling

On protocol/query errors `write` raises an error whose argument is a `map!` of server error fields
(including `sql-state`, `message`, `detail`, `hint`, etc. when present). The same map is also
available on the port as `pg/extra/last-error`.

```rebol
err: try [write pg {SELECT * FROM nonexistingtable;}]
if error? :err [
    probe err/arg1           ; map! with sql-state, message, ...
    probe pg/extra/last-error
]
```

### `write` result

`write` returns a `map!` with these keys:

- `rows`: block of row values (currently text-decoded)
- `columns`: block of column metadata maps (name, type oid, etc.)
- `command-tag`: command completion tag (e.g. `"SELECT 1"`)
- `notices`: notices received during the query
- `runtime`: collected runtime parameters (`ParameterStatus`)

### Async queries + streaming rows

The scheme supports a simple **async** API via `write` block forms. This is useful for event-driven programs where you don’t want `write` to block.

- **Async query**: returns immediately and calls completion callbacks later

```rebol
done: none
on-done: func [res] [print ["DONE tag:" res/command-tag] done: true]
on-error: func [err] [print ["ERROR:" select err 'message] done: true]

; Enqueue and return immediately:
write pg [ASYNC "SELECT 1 AS x" :on-done :on-error]

; Let the port wake as IO progresses:
until [wait [pg 5] done]
```

- **Async streaming**: delivers rows incrementally via `on-row` (does not buffer all rows in memory)

```rebol
rows-seen: 0
done: none
on-row:  func [row] [rows-seen: rows-seen + 1] ; row shaping/decoding respects row= and decode=
on-done: func [res] [print ["DONE rows:" rows-seen] done: true]
on-error: func [err] [print ["ERROR:" select err 'message] done: true]

write pg [ASYNC-STREAM "SELECT generate_series(1, 250) AS x" :on-row :on-done :on-error]
until [wait [pg 10] done]
```

Notes:

- Requests on a single connection are **processed sequentially** (Postgres protocol requires this). Async calls are queued and resolved in order.
- Callbacks are invoked from the port’s IO/awake processing; keep handlers fast and non-blocking.
- For chunked streaming (portal fetch), pass a final `max-rows` argument (e.g. `50`) to limit rows per fetch:
  - `write pg [ASYNC-STREAM "SELECT ..." :on-row :on-done :on-error 50]`
  - Optional end-of-stream hook: `write pg [ASYNC-STREAM "SELECT ..." :on-row :on-done :on-error :on-complete 50]`

### LISTEN/NOTIFY (notifications)

The scheme handles Postgres `NotificationResponse` messages at any time and can dispatch them to user callbacks.

```rebol
pgsql: import %postgres.reb
pg: open postgres://postgres:password@localhost/postgres

got: none
on-notify: func [evt][
    print ["NOTIFY channel=" evt/channel " payload=" evt/payload]
    got: evt
]

listen pg "demo_chan" :on-notify

; In another session (or same connection) send:
pgsql/notify pg "demo_chan" "hello"

until [wait [pg 10] got]
close pg
```

### CancelRequest

If the server provided `BackendKeyData`, you can cancel the currently inflight query:

```rebol
pgsql: import %postgres.reb
pg: open postgres://postgres:password@localhost/postgres

done: none
on-done: func [res][done: 'ok]
on-err:  func [err][done: err]

write pg [ASYNC "SELECT pg_sleep(10);" :on-done :on-err]
wait 0:0:0.2
pgsql/cancel pg

until [wait [pg 15] done]
close pg
```

## Examples and tests

For a fuller usage example (DDL/DML + error cases) see the test script: [`ci-test.r3`](ci-test.r3).

## Known limitations & notes

- **Single-connection concurrency**: Postgres protocol is sequential per connection; async calls are queued and resolved in order.
- **TLS verification**: TLS is currently encryption-in-transit only; certificate/CA verification is not configurable yet.
- **Logging**:
  - `log=<int>` sets `system/options/log/postgres` (scheme-wide/global).
  - Authentication payloads are redacted from logs; `trace` increases protocol verbosity but does not log secrets.
- **Handler context**: async callbacks and NOTIFY handlers run from the port’s IO/awake processing; keep them fast and non-blocking.
