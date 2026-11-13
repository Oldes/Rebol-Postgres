Rebol [Title: "Postgres extended-query packet regression checks"]
pgsql: import %postgres.reb
assert: func [condition message [string!]] [
    unless condition [print message quit/return 1]
]
packet: pgsql/make-bind-message "" "" reduce [1 "é" none true]
assert packet = #{000000000004000000013100000002C3A9FFFFFFFF00000001740000} "Incorrect Bind packet"
packet: pgsql/make-parse-message "stmt" "SELECT $1" [23]
assert packet = #{73746D740053454C45435420243100000100000017} "Incorrect Parse packet"
assert pgsql/make-sslrequest = #{0000000804D2162F} "Incorrect SSLRequest packet"
print "Postgres packet regression checks: OK"
