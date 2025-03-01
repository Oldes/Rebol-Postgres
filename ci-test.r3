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

;- Get IP of the Docker container with a running Postgres server
call/shell/output "docker ps" tmp: ""
parse tmp [thru "postgres" 55 skip copy host: to #":" to end]
if host == "0.0.0.0" [host: "localhost"]

pg: open join postgres://postgress:password@ :host
probe write pg "SELECT version();"
probe write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
try/with [write pg "SELECT unknown_function();"] :print
close pg
probe open? pg
try/with [write pg "SELECT version();"] :print
print-horizontal-line
print "DONE"