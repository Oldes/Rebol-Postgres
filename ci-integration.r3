Rebol [Title: "Postgres integration assertions"]

assert: func [condition message [string!]] [
    unless condition [print message quit/return 1]
]
pgsql: import %postgres.reb
assert module? pgsql "Embedded Postgres module not available"
system/options/log/postgres: 0
url: as url! any [get-env "PG_URL" "postgres://postgres:password@localhost/postgres"]
pg: open url
result: write pg "SELECT 42 AS answer, current_user AS username;"
assert result/rows = ["42" "postgres"] "Unexpected query result"
write pg "CREATE TEMP TABLE embedded_test (id integer PRIMARY KEY, value text);"
result: write pg [EXEC "INSERT INTO embedded_test VALUES ($1::int, $2::text) RETURNING value" [1 "embedded"]]
assert result/rows = ["embedded"] "Parameterized insert failed"
write pg [PREPARE embedded_prepared "SELECT $1::int, $2::text" [23 25]]
result: write pg [EXECUTE embedded_prepared [2 "prepared"]]
assert result/rows = ["2" "prepared"] "Prepared statement with explicit parameter OIDs failed"
write pg [DEALLOCATE embedded_prepared]
write pg "BEGIN;"
write pg "UPDATE embedded_test SET value = 'changed';"
write pg "ROLLBACK;"
result: write pg "SELECT value FROM embedded_test WHERE id = 1;"
assert result/rows = ["embedded"] "Transaction rollback failed"
err: try [write pg "SELEC 1;"]
assert error? :err "Expected SQL syntax error"
assert "42601" = select err/arg1 'sql-state "Expected SQLSTATE 42601"
result: write pg "SELECT 7;"
assert result/rows = ["7"] "Connection did not recover after SQL error"

; PostgreSQL keeps a suspended portal alive across Sync only in a transaction.
write pg "BEGIN;"
result: write pg [CURSOR embedded_cursor "SELECT generate_series(1, 7)" [] 3]
count: length? result/rows
while [select result 'more?] [
    result: write pg [FETCH embedded_cursor]
    count: count + length? result/rows
]
write pg [CLOSE-CURSOR embedded_cursor]
assert count = 7 "Chunked cursor did not return all rows"

rows-seen: 0
done: false
failed: false
on-row: func [row] [rows-seen: rows-seen + 1]
on-done: func [result] [done: true]
on-error: func [error] [failed: true done: true]
write pg [ASYNC-STREAM "SELECT generate_series(1, 20)" :on-row :on-done :on-error 5]
deadline: now/precise + 0:0:10
until [wait [pg 1] any [done now/precise > deadline]]
assert all [done not failed rows-seen = 20] "Async streaming failed"
write pg "COMMIT;"

if find form url "sslmode=require" [
    result: write pg "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
    assert result/rows = ["t"] rejoin ["Server did not confirm TLS encryption: " mold result/rows]
]
close pg
bad-url: replace copy form url ":password@" ":wrong-password@"
denied: try [open as url! bad-url]
assert error? :denied "Server accepted an incorrect password"
print "Postgres integration: OK"
