# Go API with CSRF and JWT Authentication

A lightweight Go-based API featuring secure authentication using JWTs and CSRF protection. Built for security-focused applications.

## 🔐 Features

- JWT-based login authentication
- CSRF token generation and validation
- Clean modular structure with middleware support
- RESTful endpoints for login and restricted routes

## 🚀 Getting Started

### Clone

```bash
git clone https://github.com/kunalsinghdadhwal/csrfence
cd csrfence
```

### Requirements
```
# The project needs rsa keys for jwt token generation

# Private Key
openssl genpkey -algorithm RSA -out keys/app.rsa.pem -pkeyopt rsa_keygen_bits:4096

# Public Key
openssl rsa -pubout -in keys/app.rsa.pem -out keys/app.rsa_pub.pem
```

### Build & Run

```bash
go build -o main .
```

