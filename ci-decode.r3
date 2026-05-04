Rebol [
	title: "Rebol-Postgres focused decode assertions"
	needs:  3.13.1
]

system/options/quiet: false
system/options/log/rebol: 3
system/options/log/postgres: 2

try [system/modules/postgres: none]
pgsql: import %postgres.reb

; Enforce decode + map shaping in the test URL (allow overriding host/port/user/pass).
base: any [get-env "PG_URL" "postgres://postgres:password@localhost/postgres"]
url: as url! ajoin [base "?row=map&decode=basic"]

pg: open url

assert: func [cond [any-type!] msg [string!]] [
	unless to logic! :cond [
		cause-error 'Access 'Protocol make map! reduce ['message msg]
	]
]

res: write pg "SELECT 1::int4 AS i, true::bool AS t, 1.5::float8 AS f, '2023-10-26'::date AS d;"
assert map? res "Expected result to be a map!"
assert block? res/rows "Expected rows to be a block!"
assert 1 <= length? res/rows "Expected at least one row"

row: first res/rows
assert map? row "Expected first row to be a map!"
assert integer? select row 'i "Expected i to be integer!"
assert logic? select row 't "Expected t to be logic!"
assert decimal? select row 'f "Expected f to be decimal!"
assert date? select row 'd "Expected d to be date!"

close pg
print "OK"

