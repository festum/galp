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

- Run `go run main.go`

