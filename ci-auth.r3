Rebol [
	title: "Rebol-Postgres focused auth assertions"
	needs:  3.13.1
]

system/options/quiet: false
system/options/log/rebol: 3
system/options/log/postgres: 2

try [system/modules/postgres: none]
pgsql: import %postgres.reb

assert: func [cond [any-type!] msg [string!]] [
	unless to logic! :cond [
		cause-error 'Access 'Protocol make map! reduce ['message msg]
	]
]

base: any [get-env "PG_URL" "postgres://postgres:password@localhost/postgres"]
pg: open as url! base
res: write pg "SELECT 1 AS x;"
assert map? res "Expected result map"
close pg

; Optional negative test: if PG_URL_DENY is set, it must fail to open.
deny: get-env "PG_URL_DENY"
if all [deny not empty? deny] [
	err: try [open as url! deny]
	assert error? :err "Expected open() to fail with denied auth"
]

print "OK"

