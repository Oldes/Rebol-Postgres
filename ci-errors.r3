Rebol [
	title: "Rebol-Postgres focused error assertions"
	needs:  3.13.1
]

system/options/quiet: false
system/options/log/rebol: 3
system/options/log/postgres: 2

try [system/modules/postgres: none]
pgsql: import %postgres.reb

pg-url: any [get-env "PG_URL" "postgres://postgres:password@localhost/postgres"]
pg: open as url! pg-url

assert: func [cond [any-type!] msg [string!]] [
	unless to logic! :cond [
		cause-error 'Access 'Protocol make map! reduce ['message msg]
	]
]

expect-error: func [code [block!] /local err] [
	err: try code
	assert error? :err "Expected an error, got success"
	assert map? err/arg1 "Expected error arg1 to be a map!"
	err/arg1
]

; Syntax error should have SQLSTATE 42601 and position
e: expect-error [write pg "SELEC 1;"]
assert (select e 'sql-state) = "42601" ajoin ["Expected 42601, got " mold select e 'sql-state]
assert not none? (select e 'position) "Expected syntax error to have position"

; Missing relation should have SQLSTATE 42P01
e: expect-error [write pg "SELECT * FROM nonexistingtable;"]
assert (select e 'sql-state) = "42P01" ajoin ["Expected 42P01, got " mold select e 'sql-state]

close pg
print "OK"

