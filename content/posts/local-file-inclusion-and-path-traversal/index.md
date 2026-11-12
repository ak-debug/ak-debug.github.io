---
title: "Path Traversal and LFI: Reading Files the App Never Meant to Serve"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "When a web app takes a filename from the user and reads it off disk, a few ../ sequences can walk out of the intended directory and into anything the server can read. Here I cover path traversal end to end, including a filter-bypass trick for when the app tries to strip dangerous input, using two DD CTF challenges as worked examples."
tags: ["web-security", "path-traversal", "lfi", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

Plenty of web applications read a file from disk based on something the user supplies: a `file=` parameter, a document name, a template to render. If the application concatenates that value into a path and reads it without validation, an attacker can supply `../` sequences to climb out of the intended directory and read arbitrary files. That is **path traversal**, and when the file's contents come back in the response it is often called **Local File Inclusion (LFI)**.

This post works through two challenges from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)): a straightforward traversal, and a second one that adds a naive filter you have to defeat. The technique matters more than the specific challenges; this bug class still leaks source code, configuration, and credentials from real applications.

> **Scope and ethics.** Both targets were deliberately vulnerable applications from a CTF that has ended. Only test this against systems you own or are authorised to assess.

## The vulnerable pattern

Conceptually the server is doing something like this:

```php
$file = $_GET['file'];          // attacker-controlled
echo file_get_contents($file);  // or "pages/" . $file
```

The application expects `file` to be a well-behaved name like `membership.txt`. But nothing stops the value from being `../../../../etc/passwd`. Each `../` moves up one directory, so with enough of them you reach the filesystem root and can then walk back down to any path the server process is allowed to read.

## Challenge 1: a plain traversal

The first challenge exposes a "membership" feature that prints a file. The request carries the filename in a `file` parameter, and the challenge tells us the flag is at `/flag.txt`. Since the browser's UI didn't let me edit the value directly, I intercepted the request in Burp Suite and tried increasing traversal depth:

```http
file=flag.txt
file=../flag.txt
file=../../flag.txt
```

`../../flag.txt` returned the file. The first two didn't resolve to the right place because the application prepends its own directory to the name, so I needed to climb two levels before naming the file. The response contained the flag, `bi0s{...}`.

One detail worth internalising: the same parameter was also reflected in the URL, so the traversal worked by editing the query string directly in the browser too. Burp made iterating faster, but the vulnerability was in the parameter, not in any particular tool. When you find one injection point, check whether the same value is controllable somewhere more convenient.

## Challenge 2: defeating a naive filter

The sequel "makes the app more secure," and the description drops a hint: *nothing is a **replace**ment for spaces*. The emphasis on "replace" is the tell. The application takes a filename (it was printing a poem, `Themoon.txt`), and when I asked for `flag.txt`, the response came back as just `.txt`. The word `flag` had been stripped out.

This is a classic mistake: the filter does a **single, non-recursive replacement**, removing the substring `flag` once, in place, and then uses what's left. Any filter that removes a bad token by deleting it can be beaten by splitting the token so that the deletion *reassembles* it.

I'd seen the same trick defeating a `<script>` filter in DVWA, where `<sc<script>ript>` survives because removing the inner `<script>` leaves the outer letters to join back into `<script>`. The identical idea works here. I sent:

```text
flflagag.txt
```

The filter finds the inner `flag`, deletes it, and the remaining `fl` + `ag` close up into `flag.txt`. The file name is reconstructed *after* the filter has already run, so the check never sees it.

With the filter beaten, the rest is the same traversal as before. The flag for this challenge lived at `/tmp/flag.txt`, so I combined the split-token bypass with directory traversal to climb to the target and read it, again getting `bi0s{...}`.

## Why the filter bypass works (and why it's the wrong defence)

The split-token bypass works because the filter treats the input as a string to clean rather than a value to validate, and because it runs exactly once. There will always be a split that survives a single pass. Chaining removals, applying them recursively, or trying to enumerate "bad" substrings is a losing game; a blocklist of dangerous patterns can nearly always be smuggled past.

## Defending against path traversal

- **Don't put user input in a path.** Map a fixed set of allowed values to known files server-side: `{"moon": "Themoon.txt"}`. The user picks a key, never a path.
- **If you must accept a name, canonicalise and confine it.** Resolve the final absolute path (for example with `realpath`) and verify it is still inside the intended base directory before reading. Reject anything that escapes.
- **Strip the directory component.** A function like `basename()` discards any `../` and leading directories, so only a bare filename remains.
- **Run with least privilege.** The server process should not be able to read `/etc/passwd`, application secrets, or other users' files in the first place.

Note that every one of these is an *allowlist* or *containment* control. None of them is "remove the bad word", which is exactly the approach the second challenge showed you can defeat.

## Takeaways

- **`../` is the whole attack.** Any endpoint that reads a user-named file is a candidate; vary the traversal depth because the app usually prepends its own directory.
- **Blocklist filters invite bypasses.** A single-pass replace can be beaten by splitting the token so it reassembles after filtering (`flflagag` to `flag`). Validate against an allowlist or confine the resolved path instead.
- **Check every place the value appears.** The same parameter was editable in the URL and in the intercepted request; find the easiest controllable injection point.

*Worked examples: "laughable file infiltration" and "laughable file infiltration 2", DD CTF by team bi0s. Flags redacted as `bi0s{...}`.*
