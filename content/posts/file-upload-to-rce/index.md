---
title: "From File Upload to Remote Code Execution"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "If a web server lets you upload a file and will later execute it, an upload form becomes a way to run your own code on the server. Here I walk through confirming PHP execution with a harmless test payload and then reading a protected file, plus why 'store the upload in the webroot' is the real mistake."
tags: ["web-security", "file-upload", "rce", "php", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

An unrestricted file upload becomes remote code execution (RCE) when two conditions hold: the server stores a file you control somewhere it will serve, and the server will *execute* that file rather than just hand back its bytes. For a PHP application, uploading a `.php` file into a reachable directory means that requesting it runs your code on the server, with all the access the web process has.

This post works through the "Ghost" challenge from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)), where an upload feature allowed exactly that. The challenge promised "state-of-the-art" file protection; the upload handler delivered none.

> **Scope and ethics.** The target was a deliberately vulnerable CTF application that has since been retired. Only test file-upload behaviour against systems you own or are authorised to assess.

## Spotting the backend

The first clue was the stack. The application's pages were served as `index.php`, which tells you the backend is PHP. That matters because it means an uploaded `.php` file, if it lands somewhere served by the PHP interpreter, will be *run* when requested, not downloaded. Knowing the server-side language shapes the payload: the same bug on an ASP or JSP app needs a `.aspx` or `.jsp` file instead.

## Step 1: confirm code execution with a harmless payload

Before doing anything else, I wanted to prove that an uploaded script actually executes, with the smallest possible test. Guessing at the final exploit is slower and noisier than confirming the primitive first. I uploaded a one-line PHP file that just prints a marker:

```php
<?php
echo 'Test payload executed successfully.';
?>
```

Then I visited the uploaded file's URL. The page returned `Test payload executed successfully.` — not the source text of the script, but its *output*. That confirms two things at once: the upload was stored somewhere reachable, and the server executed it as PHP. From here it's not "can I get RCE?" but "what do I want my code to do?".

## Step 2: read the target file

The challenge placed the flag at `/tmp/flag.txt`, so I uploaded a second script that reads and prints it:

```php
<?php
$flagPath = '/tmp/flag.txt';

if (file_exists($flagPath)) {
    $flagContents = file_get_contents($flagPath);
    echo '<pre>' . htmlspecialchars($flagContents) . '</pre>';
} else {
    echo 'Flag file not found.';
}
?>
```

Visiting the new file's URL ran the script and printed the contents of `/tmp/flag.txt`, giving the flag `bi0s{...}`. The `htmlspecialchars` and `<pre>` are just so the output renders cleanly in the browser; the real work is `file_get_contents` running server-side with the web process's privileges.

This is deliberately restrained, reading one file, but the same primitive is full code execution. The script could list directories, read application config and database credentials, or run shell commands. Once arbitrary code runs on the server, the application's boundary is gone.

## Why it happened

The root cause is that the handler accepted a file whose type it should never execute, and stored it where the interpreter would run it. Any of several missing checks would have broken the chain:

- It didn't restrict the upload to expected types (it should only ever have accepted, say, images).
- It kept the attacker-controlled extension (`.php`) instead of assigning a safe one.
- It wrote the file into a directory the PHP engine serves and executes.

## Defending against malicious uploads

- **Validate type by content, not just extension.** Check the real file signature / MIME type and enforce an allowlist of expected formats. Never trust the client-supplied filename or `Content-Type` alone.
- **Never execute uploaded files.** Store uploads *outside the webroot* and serve them through a handler that returns bytes with a safe content type, or from object storage on a separate domain. If uploads must live under the webroot, disable script execution for that directory in the server config.
- **Rename on upload.** Generate a random server-side name and a safe extension so an attacker can't choose `.php`.
- **Run with least privilege** so that even successful RCE is contained.

## Takeaways

- **Upload plus execution equals RCE.** The vulnerability isn't "I uploaded a file"; it's that the server ran it.
- **Fingerprint the backend first.** `index.php` told me a `.php` payload would execute; match the payload to the server-side language.
- **Confirm the primitive with a tiny payload** before building the real one, then escalate.
- **The fix is to never execute uploads,** stored outside the webroot with validated types and server-assigned names, not to blocklist extensions.

*Worked example: "Ghost", DD CTF by team bi0s. Flag redacted as `bi0s{...}`.*
