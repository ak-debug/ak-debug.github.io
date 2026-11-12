---
title: "Broken Access Control: IDOR and Cookie Tampering"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "When the server trusts a value the client can change to decide who you are or what you can see, you can often just change it. Here I cover two sides of broken access control: tampering with a client-side cookie to become an admin, and incrementing an ID in the URL to read someone else's record, using two DD CTF challenges as worked examples."
tags: ["web-security", "access-control", "idor", "cookies", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

Broken access control is consistently the number-one risk on the OWASP Top Ten, and the reason is simple: it isn't one clever bug, it's the server trusting the client to tell the truth about identity or authorisation. If a cookie says `admin=0` and the server believes it, you change it to `admin=1`. If a URL says `id=1` and the server fetches that record without checking it's yours, you ask for `id=0`.

This post covers both patterns with challenges from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)): "CookieMonster" (tampering with a client-side cookie) and "PhoneBook" (an insecure direct object reference, or IDOR). They look different but share one root cause.

> **Scope and ethics.** Both were deliberately vulnerable CTF targets that have since been retired. Only test access control against systems you own or are authorised to assess.

## Pattern 1: cookie tampering (CookieMonster)

The challenge name points at cookies, so I intercepted a request in Burp Suite and looked at the one the application set. The value wasn't plaintext, so I ran it through [CyberChef](https://gchq.github.io/CyberChef/) and tried common encodings. **Base64** decoded it into a readable structure containing an admin flag set to `0`.

That is the whole vulnerability: the application stored the user's privilege level in a cookie, base64-encoded, and trusted it on the way back in. Base64 is an *encoding*, not encryption or a signature, so anyone can decode it, change it, and re-encode it. I flipped the admin value to `1`, re-encoded with base64, and replaced the cookie.

One practical snag worth recording: the cookie in transit was URL-encoded, so the `=` padding showed up as `3D`. I had to work with the correctly decoded value rather than the URL-escaped one; submitting the mangled version got nothing. With the clean, re-encoded `admin=1` cookie in place, the server treated me as an administrator and returned the flag `bi0s{...}`.

The lesson is that a cookie is client-side data. Anything you put in it, the client can read and rewrite unless it is cryptographically protected.

## Pattern 2: insecure direct object reference (PhoneBook)

The second challenge is an IDOR. The site let me view "my" contact, and the request carried an identifier in the URL, `account id=1`. The application used that id to look up a record and return it, without checking that the record actually belonged to me.

So I changed the id. Setting it to `0` returned a different account's data, the administrator's, which held the flag. No encoding, no tooling, just editing a number in the URL. The server exposed a *direct reference* to a database object (the account id) and performed no *authorisation* check on it.

This is the same trust failure as the cookie, in a different coat. In CookieMonster the server trusted a client value to decide *what role I had*; in PhoneBook it trusted a client value to decide *which object I could access*. In both cases the client controls the input and the server fails to verify it.

## Why these share one root cause

Access control decisions must be made on the server, using state the client cannot forge, and must be checked on every request for every object. Both challenges broke that rule:

- CookieMonster put the *authorisation state* (am I admin?) somewhere the client controls.
- PhoneBook performed *no object-level authorisation* (is this record mine?) at all.

If you find one of these on an assessment, it is always worth testing the other. Any client-supplied id, GUID, filename, or role value is a candidate.

## Defending against broken access control

- **Decide authorisation server-side, from trusted state.** Derive the user's identity and role from a server-side session, never from a client-set field.
- **Make session tokens opaque and integrity-protected.** Use a random session id that maps to server-side data, or a signed token (such as a properly verified JWT). A base64 blob of `admin=0` is neither.
- **Enforce object-level checks every time.** Before returning object `id`, confirm the authenticated user is allowed to see *that specific object*. Don't rely on the UI not showing a link.
- **Prefer unpredictable identifiers** (random UUIDs) so references can't be trivially enumerated, but treat that as defence in depth, not a substitute for authorisation checks.
- **Default deny.** Access should be denied unless a check explicitly allows it.

## Takeaways

- **If the client can change it, the client will.** Cookies and URL parameters are attacker-controlled input.
- **CookieMonster and PhoneBook are the same bug.** One forges a role, the other forges an object reference; both exist because the server trusted client input for an authorisation decision.
- **Fix it on the server.** Opaque, integrity-protected sessions plus per-object authorisation checks on every request.

*Worked examples: "CookieMonster" and "PhoneBook", DD CTF by team bi0s. Flags redacted as `bi0s{...}`.*
