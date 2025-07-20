# ZatsuPGP

ZatsuPGP is implementation **to learn** OpenPGP.  
(You **SHOULD NOT** use this module on production environment)

It aims to implement part of OpenPGP specification with Go standard library only.

## Setup

```shell
git checkout git@github.com:murakmii/ZatsuPGP.git && cd ZatsuPGP

gpg --version | head -1
gpg (GnuPG) 2.4.7

# Generate keys by GnuPG and export them.
gpg --gen-key --batch misc/sample_key.conf
gpg -k
.../pubring.kbx
------------------
pub   rsa2048 2025-07-20 [SCEAR]
      12B1253603E5ED3C1EBBEE944CCCF8C8B20237D3
uid           [ultimate] Alice <alice@example.com>

gpg -o pub.pgp --export 12B1253603E5ED3C1EBBEE944CCCF8C8B20237D3
gpg -o sec.pgp --export-secret-keys 12B1253603E5ED3C1EBBEE944CCCF8C8B20237D3

# Build ZatsuPGP
go build -o zatsu cmd/zatsu.go
```

## Dump

```shell
./zatsu dump-public-key ./pub.pgp
User ID: Alice <alice@example.com>
Key ID: 4cccf8c8b20237d3
Key length: 2048
Created at: 2025-07-20 15:12:06 +0900 JST

./zatsu dump-private-key ./sec.pgp 'pa$$w0rd'
User ID: Alice <alice@example.com>
Key ID: 4cccf8c8b20237d3
Key length: 2048
S2K: iter+salt(65011712:54c837b3fdfc7979)
IV: 8a3759f1984e133dc96e2f9e0b0fd9f4
Decryption test: OK
```

## Encryption

```shell
 ./zatsu encrypt ./pub.pgp sample.txt 'Hello, OpenPGP' > ./by_zatsu.pgp
 
 # Check by GnuPG
gpg -d /gnupg/by_zatsu.pgp
gpg: encrypted with rsa2048 key, ID 4CCCF8C8B20237D3, created 2025-07-20
      "Alice <alice@example.com>"
Hello, OpenPGP
```

## Decryption

```shell
# Encrypt sample data by GnuPG
echo 'This is sample message by GnuPG!' > ./by_gpg.txt
gpg --compress-algo none -o ./by_gpg.pgp -e -r 'alice@example.com' ./by_gpg.txt

./zatsu decrypt ./by_gpg.pgp ./sec.pgp 'pa$$w0rd'
Decrypted data: by_gpg.txt(created at: 2025-07-20 15:39:40 +0900 JST)
This is sample message by GnuPG!
```
