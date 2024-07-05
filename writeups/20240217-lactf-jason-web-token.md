Jason Web Token
LA CTF 2024
augusto, rickbonavigo
# Introduction

In this challenge, we are given a custom implementation of a JWT-like token system. And we have to break it.

# Source Code Analysis

After checking out the app source code, we isolated the _interesting_ part which is reported below.

```python
import hashlib
import json
import os
import time

secret = int.from_bytes(os.urandom(128), "big")
hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

def create_token(**userinfo):
    userinfo["timestamp"] = int(time.time())
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]
    data = json.dumps(userinfo)
    return data.encode().hex() + "." + hash_(f"{data}:{salted_secret}")

def decode_token(token):
    if not token:
        return None, "invalid token: please log in"

    datahex, signature = token.split(".")
    data = bytes.fromhex(datahex).decode()
    userinfo = json.loads(data) 
    salted_secret = (secret ^ userinfo["timestamp"]) + userinfo["age"]

    if hash_(f"{data}:{salted_secret}") != signature:
        return None, "invalid token: signature did not match data"
    return userinfo, None
```

# Finding an attack surface

We asked our dear crypto-guys to check out the token generation, signing, and verification logic. After some discussion, they confirmed the initial suspicion: the crypto was sound as long as the secret couldn't be leaked, which didn't seem to be possible. That was our confirmation that the challenge was indeed a _pure_ web challenge and not some mix of web and crypto stuff.

Proper input validation was in place because the application uses [FastAPI](https://fastapi.tiangolo.com/) which relies on [Pydantic](https://pydantic.dev/) to validate the types used in the API requests.

What we noticed, however, is that the received token fields are not really validated in any way before being used.

# Juggling types for fun and profit

So we started playing around with the only part we could control, starting with the values used to salt the secret:
- `timestamp`: is XORed with the secret. In Python, XORing an integer with anything that's not an integer results in a `TypeError`... unlucky. So it couldn't be changed to anything other than an int.
- `age`: is added to `secret ^ timestamp`. Wait... What happens if it's a float instead of an int?

# Bingo!

Adding floats can easily cause weird things to happen, for example `NaN`s or various sorts of `infinity`s.

Thanks to the magical properties of floating point numbers we know that near the representable limits we have a loss of precision which manifests in the following ways:
- Summing to `sys.float_info.max` a number smaller than \(10^{291}\), is still represented as the max representable float, `sys.float_info.max`.
- Summing a number just higher (\(10^{292}\) or above), yields `+infinity` instead.

The secret is a 128 bytes long random number, which has an extremely high probability of being higher than \(10^{292}\).

This means that summing `secret ^ timestamp` with `sys.float_info.max` is always going to be `+infinity`, which Python represents as `inf`.

Thus, we can forge a "Jason Web Token" as we wish because we know that `salted_secret` will be `inf`. Thus creating a token with the `admin` role is trivial.

# The exploit

```python
import requests
import hashlib

hash_ = lambda a: hashlib.sha256(a.encode()).hexdigest()

data = '{"username": "UncleTed", "role": "admin", "age": 1e+309, "timestamp": 0}'
token = data.encode().hex() + '.' + hash_(data+':inf')
requests.get('https://jwt.chall.lac.tf/img', cookies={'token': token}).text
```

The flag revealed is: `lactf{pr3v3nt3d_th3_d0s_bu7_47_wh3_c0st}`

# Considerations

The flag didn't make any sense to us, which suggested that the exploit used was not really the intended one. A quick chat with the authors confirmed our suspicions. We just knew it involved using a DoS to somehow extract information about the secret.

After a bit of googling, we found [an interesting article](https://blog.tal.bi/posts/python-int-str-conversion-limits/) about integer-to-string conversion in Python 3.10: it operates in \(O(d^2)\) time, where \(d\) is the length in digits of the number. This behavior was changed in Python 3.11: integers are now capped at 4300 digits by default.

The challenge was indeed using Python 3.10, as we can see in the first line of the `Dockerfile`: `FROM python:3.10`.

We weren't motivated enough to implement the intended solution because we already got our nice flag, so we won't explain how that should have worked.