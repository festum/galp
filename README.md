# GALP (go-auth-ldap-proxy)

A reverse proxy provides authentication using LDAP and extra auth source to validate accounts by email. Inspired by [bitly/oauth2_proxy](https://github.com/bitly/oauth2_proxy).
Many SME using LDAP to manage their employee accounts. Sometimes developer just want to expose internal services and limited access for only employees.

This proxy will going to check accounts credentials from LDAP and extra storage. Then set a JWT token on the domain. 
Each request will validate this token and pass request with identity to internal service if valid.

## Getting Start

- Generate a key for encryption

```
cd galp
ssh-keygen -t rsa -b 2048 -f daRS256.key
openssl rsa -in daRS256.key -pubout -outform PEM -out daRS256.key.pub
```

- Edit variables

```
cp .env.sample .env
vim .env
```

- Build
```
go build -o=galp src/github.com/festum/go-ldapauth/cli.go
go build -o=galp-server src/github.com/festum/go-ldapauth/main.go
```

- Add a new user: `./galp user add user1 password`

- Run server: `./galp-server`



## Flavor

- [BadgerDB](https://github.com/dgraph-io/badger) - It's the [fastest](https://blog.dgraph.io/post/badger/) KV storage using LSM-trees based on [WiscKey: Separating Keys from Values in SSD-conscious Storage](https://www.usenix.org/system/files/conference/fast16/fast16-papers-lu.pdf)
- [Chi](https://github.com/go-chi/chi) - A lightweight, idiomatic and composable router with good middleware supported
- [Docopt.go](https://github.com/docopt/docopt.go) - Pythonic command line arguments parser, just fits tiny cli tool