FROM postgres:17

# Force server to store MD5 password hashes (so md5 auth can succeed)
CMD ["postgres", "-c", "password_encryption=md5"]

