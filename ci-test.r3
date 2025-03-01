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

pg: open postgres://postgress:password@localhost
probe write pg "SELECT version();"
probe write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
try/with [write pg "SELECT unknown_function();"] :print
close pg
probe open? pg
try/with [write pg "SELECT version();"] :print
print-horizontal-line
print "DONE"