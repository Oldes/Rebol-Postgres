Rebol [
	title: "SQLite extension test"
	needs:  3.13.1 ;; using system/options/modules as extension location
]

print ["Running test on Rebol build:" mold to-block system/build]

system/options/quiet: false
system/options/log/rebol: 4

;; make sure that we load a fresh extension
try [system/modules/postgres: none]

pgsql: import %postgres.reb

system/options/log/postgres: 3

foreach [title code] [
	"Opening a connection" [
		pg: open postgres://postgress:password@localhost
	]

	"Simple query (get PostgreSQL version)" [
		probe write pg "SELECT version();"
	]

	"Simple query (get list of all databases)" [
		probe write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
	]

	"Trying to call a not existing function (error expected)" [
		try/with [write pg "SELECT unknown_function();"] :print
	]

	"Closing the connection" [
		close pg
	]

	"Testing that the connection is closed" [
		probe open? pg
	]

	"Trying to write to the closed connection (error expected)" [
		try/with [write pg "SELECT version();"] :print
	]

][
	print-horizontal-line
	print as-yellow title
	print as-blue form code
	prin LF
	do code
]


print "DONE"