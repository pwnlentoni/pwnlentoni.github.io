# Alternating

Category: forensics

Flag: `ctf{7ce5567830a2f9f8ce8a7e39856adfe5208242f6bce01ca9af1a230637d65a2d}`

Description:
> We have hidden something in the file and I'm sure you won't find it. Make sure to extract the archive using WinRar. Windows is your friend.

## Solution

The challenge provides a file, Flag.rar, that when extracted produces a file named `Flag.txt.txt`,
which is sadly empty.
Although the challenge description mentioned Windows,
I didn't have a Windows device available,
so the first thing I did was opening the file in an hex editor.
I was presented with this:

```
00000000: 5261 7221 1a07 0100 3392 b5e5 0a01 0506  Rar!....3.......
00000010: 0005 0101 8080 00ae 1822 e228 0203 0b80  .........".(....
00000020: 0004 8000 2000 0000 0080 0000 0c46 6c61  .... ........Fla
00000030: 672e 7478 742e 7478 740a 0302 c86c 5194  g.txt.txt....lQ.
00000040: 7269 da01 a012 5452 2603 2310 cb80 0004  ri....TR&.#.....
00000050: ca80 0000 c472 0a1c 8003 0003 5354 4d0f  .....r......STM.
00000060: 073a 7265 616c 5f66 6c61 672e 7478 74c6  .:real_flag.txt.
00000070: d448 3554 442f 7404 2ee4 821c 9882 cd06  .H5TD/t.........
00000080: 5e84 e597 a104 7320 fda5 354a f7d6 5ee1  ^.....s ..5J..^.
00000090: e525 9fda f8de 77b2 34d5 db34 b48f 28c7  .%....w.4..4..(.
000000a0: 3a54 1e34 503c dd33 d812 f005 f0ec ad58  :T.4P<.3.......X
000000b0: 1052 d1c1 6c66 3fb7 5cf0 1d77 5651 0305  .R..lf?.\..wVQ..
000000c0: 0400                                     ..
```

We can see that the file is pretty small,
and if we look carefully at the ASCII interpretation of the file,
we can spot that the string `real_flag.txt` appears.

Running `file Flag.rar` reveals that the given archive is a RAR v5 archive.
The RAR 5.0 specification has a helpful [General Archive Layout](https://www.rarlab.com/technote.htm#arclayout) section which
explains how a RAR file is composed:
after a header at the beginning of the file,
there is an array of file headers,
and each of them can optionally have one or more service headers.
If we scroll down a bit further,
the specification also explains how the file headers and service headers are structured;
interestingly, both types of headers are almost identical,
the only difference being the Header Type field,
which is `2` for a file header and `3` for a service header.

At this point, I hypothesized that the `Flag.txt.txt` string belonged to a file header,
while the `real_flag.txt` was a service header which was being ignored.
Since the Header Type field is located before the Name,
i walked backwards from the first character of `real_flag.txt` until I found a `0x03` byte,
with the hex editor changed that to a `0x02`, exported the file, and tried to extract it.
That still produced only `Flag.txt.txt`,
so I undid the change and repeated it on the previous `0x03`,
which also didn't work.
Luckily, as the old saying goes, third time's the charm: after patching the byte at offset 0x49,
two files were extracted: `Flag.txt.txt`, which was again empty, and a new file named `STM`, which 
contained the flag.
