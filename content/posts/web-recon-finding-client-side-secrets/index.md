---
title: "Web Recon: Finding Secrets in Source, robots.txt, and Client-Side Storage"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "Developers keep hiding data in places the browser can read: HTML comments, robots.txt, hidden fields, and local storage. None of it is secret. Here I reassemble a flag split across the page source, a robots.txt disallow entry, and an inspected value, and explain why client-side is never a hiding place."
tags: ["web-security", "recon", "osint", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

A surprising amount of web security starts with simply *looking*. Before any payload, the page source, HTTP responses, cookies, `robots.txt`, and browser storage often hand you information the developer assumed no one would check. The recurring mistake is treating "the user won't see it" as "the user can't see it". Everything the browser receives is visible to whoever controls the browser.

This post uses the "Partly_Stored Answers" challenge from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)), where the flag was deliberately scattered across several of these client-side hiding places and had to be reassembled.

> **Scope and ethics.** The target was a deliberately vulnerable CTF application that has since been retired. Passive recon like this is still only appropriate against systems you own or are authorised to assess.

## Start with the basics: source, requests, cookies

My first pass on any web challenge is the unglamorous one: read the HTML source, watch the requests in the network tab, and look at the cookies. Here that paid off immediately. An HTML comment in the page source held the first fragment of the flag:

```html
<!-- The First part of flag: bi0s{....(redacted).... -->
```

HTML comments are stripped from the rendered page but sit in plain view in "View Source". They are a classic place to find debugging notes, credentials, and, as here, part of a flag.

## robots.txt: a map of what they'd rather you skip

Stuck after the first fragment, the challenge's robot theme nudged me toward `robots.txt`. That file tells search-engine crawlers which paths *not* to index, which means it often enumerates exactly the paths a developer considers sensitive:

```text
User-agent: *
Disallow: /some-hidden-path
```

`robots.txt` is advisory; it does not restrict access, it just asks crawlers politely to stay away. For anyone doing recon it's a free list of interesting routes. Visiting the disallowed path, and again reading its source, revealed the second fragment of the flag in another HTML comment:

```html
<!-- the second part of the flag : ....(redacted).... -->
```

## Inspect the page for "hidden" values

The disallowed route also had a value that wasn't shown on screen but was present in the DOM. Opening the browser's element inspector surfaced a secret value (here `57579`) sitting in the markup. "Hidden" in HTML, via a `hidden` attribute, CSS `display:none`, or a disabled field, only affects rendering; the value is still right there in the inspector. Submitting that secret on the home page, as the challenge asked, returned the final piece.

Concatenating the fragments gave the complete flag, `bi0s{...}`.

## Where else client-side secrets hide

The same challenge family also hides data in browser storage. It's worth checking, every time:

- **`localStorage` and `sessionStorage`** (Application tab in dev tools) often hold tokens, feature flags, or cached user data.
- **Cookies**, including values that are base64 or URL-encoded rather than truly protected.
- **JavaScript bundles**, which frequently contain API endpoints, keys, and commented-out logic.
- **Source maps** (`.js.map`), which can reconstruct original source.

## The underlying lesson (and the defence)

Every one of these is the same mistake: putting something sensitive where the client can read it and assuming obscurity equals security. The fix is architectural, not cosmetic:

- **Keep secrets server-side.** If the browser must not see a value, it must never be sent to the browser, not in comments, hidden fields, storage, or JS.
- **Don't rely on `robots.txt` or "hidden" attributes for protection.** They control indexing and rendering, not access. Protect sensitive routes with real authentication and authorisation.
- **Treat anything shipped to the client as public.** Minification and obfuscation slow someone down; they don't stop them.

## Takeaways

- **Look before you exploit.** Source, requests, cookies, `robots.txt`, and storage routinely leak information for free.
- **"Hidden" is a rendering state, not a security control.** The inspector shows what the screen doesn't.
- **Obscurity is not security.** If the browser receives it, treat it as public, and keep real secrets on the server.

*Worked example: "Partly_Stored Answers", DD CTF by team bi0s. Flag redacted as `bi0s{...}`.*
