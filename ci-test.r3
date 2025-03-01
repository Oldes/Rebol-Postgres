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
		write pg "SELECT version();"
	]

	"Simple query (get list of all databases)" [
		write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
	]

	"Trying to call a not existing function (error expected)" [
		write pg "SELECT unknown_function();"
	]

	"Closing the connection" [
		close pg
	]

	"Testing that the connection is closed" [
		open? pg
	]

	"Trying to write to the closed connection (error expected)" [
		write pg "SELECT version();"
	]

][
	prin LF
	print-horizontal-line
	print as-yellow join ";; " title
	prin as-red ">> "
	print as-white mold/only code
	prin LF
	set/any 'result try code
	either error? :result [
		print result
	][
		print as-green ellipsize ajoin ["== " mold :result] 300
	]
]


print "DONE"