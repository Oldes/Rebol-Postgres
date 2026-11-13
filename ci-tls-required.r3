Rebol [Title: "Required TLS must reject a plaintext-only PostgreSQL server"]
import %postgres.reb
url: as url! get-env "PG_URL"
err: try [open url]
unless error? :err [
    close err
    print "sslmode=require unexpectedly opened a plaintext connection"
    quit/return 1
]
unless find mold err "Server does not support TLS" [
    print err
    quit/return 1
]
print "Required TLS refusal: OK"
