---
title: "LA CTF 2024 — Jason Web Token"
date: 2024-02-17
draft: false
tags: ["web", "crypto", "jwt", "type-juggling", "python"]
categories: ["LA CTF 2024"]
authors: ["augusto", "rickbonavigo"]
summary: "Abusing Python's floating point arithmetic to forge JWT-like tokens — when float('inf') meets type juggling."
---

## Introduction

In this challenge, we are given a custom implementation of a JWT-like token system. And we have to break it.

## Source Code Analysis

```python
secret = int.from_bytes(os.urandom(128), "big")
hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

def create_token(**userinfo):
    userinfo["timestamp"] = int(time.time())
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]
    data = json.dumps(userinfo)
    return data.encode().hex() + "." + hash_(f"{data}:{salted_secret}")

def decode_token(token):
    datahex, signature = token.split(".")
    data = bytes.fromhex(datahex).decode()
    userinfo = json.loads(data)
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]
    if hash_(f"{data}:{salted_secret}") != signature:
        return None, "invalid token: signature did not match data"
    return userinfo, None
```

## Finding the vulnerability

The crypto was sound as long as the secret couldn't be leaked. Proper input validation was in place via FastAPI + Pydantic. But the received token fields are not validated before being used in the signing logic.

We started playing with the values used to salt the secret:
- `timestamp`: XORed with the secret — must be an int
- `age`: **added** to `secret ^ timestamp` — what if it's a float?

## Bingo!

Thanks to floating point arithmetic: summing `secret ^ timestamp` (a huge integer) with `sys.float_info.max` yields `+infinity`. Python represents this as `inf`.

This means `salted_secret` will **always** be `inf` regardless of the actual secret, making token forgery trivial.

## Exploit

```python
import requests
import hashlib

hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

data = '{"username": "UncleTed", "role": "admin", "age": 1e+309, "timestamp": 0}'
token = data.encode().hex() + '.' + hash_(data+':inf')
requests.get('https://jwt.chall.lac.tf/img', cookies={'token': token}).text
```

**Flag:** `lactf{pr3v3nt3d_th3_d0s_bu7_47_wh3_c0st}`

## Considerations

The flag suggested the intended solution was different — it involved using a DoS via Python 3.10's O(d²) integer-to-string conversion to extract information about the secret. But our float overflow approach was simpler and equally effective.
