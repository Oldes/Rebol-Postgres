FROM postgres:17

# PostgreSQL 17 stores passwords as scram-sha-256 by default.  When pg_hba
# uses the "password" (cleartext) auth method and the stored hash is in SCRAM
# format, the server upgrades the auth challenge to SCRAM (type 10) instead of
# sending a cleartext prompt (type 3).  Storing passwords as md5 lets the
# server honour the "password" pg_hba method and send the expected type-3
# challenge.
CMD ["postgres", "-c", "password_encryption=md5"]
