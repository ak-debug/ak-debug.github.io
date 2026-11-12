---
title: "SQL Injection: Bypassing a Login with OR 1=1"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "A login form that builds its SQL query by pasting your input into a string can be talked into authenticating you as someone else. Here I walk through turning a SQL error into a login bypass with a classic OR '1'='1' payload, why it works at the query level, and how parameterised queries end the whole bug class."
tags: ["web-security", "sql-injection", "authentication", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

SQL injection happens when an application builds a SQL query by concatenating untrusted input directly into the query string. Because the input lands in the same text the database parses as code, an attacker can break out of the data context and change what the query *does*. On a login form, that means you can turn "find the user whose password matches" into "find any user at all", and authenticate without credentials.

This post uses the "secretkeeper" login-bypass challenge from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)) as the worked example. SQL injection is old, but it still sits near the top of the OWASP list because the vulnerable pattern keeps getting rewritten.

> **Scope and ethics.** The target was a deliberately vulnerable application from a CTF that has ended. Only test SQL injection against systems you own or are explicitly authorised to assess.

## The vulnerable pattern

A login backed by SQL usually runs a query shaped like this:

```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>';
```

If the application inserts the submitted username and password straight into that string, your input is sitting *inside the quotes* as far as the developer intended, but the database only sees one flat string of SQL. If you can introduce a quote of your own, you leave the data and start writing query logic.

## Finding the injection point

The site is just a login form, so the first thing I tried was a single quote in the username to see whether input reached the query unescaped. The response came back with a **SQL syntax error**. That error is the signal: my quote changed the structure of the query enough to break its grammar, which means the input is being parsed as SQL, not treated as a plain value. A form that is safe would have simply rejected the login; one that leaks a SQL error is almost always injectable.

Because I expected to iterate on payloads, I moved the request into Burp Suite's Repeater so I could tweak and resend quickly rather than retyping in the browser.

## The bypass payload

The payload that worked:

```text
username=ak' OR '1'='1' #
password=anything
```

To see why, substitute it into the query template:

```sql
SELECT * FROM users WHERE username = 'ak' OR '1'='1' #' AND password = 'anything';
```

Two things happen:

- **`OR '1'='1'`** makes the `WHERE` clause true for every row. `'1'='1'` is always true, and `OR` means the whole condition passes regardless of the username. The query now returns users instead of none.
- **`#`** is a MySQL comment. Everything after it, including the ` AND password = '...'` check and the trailing quote the app appended, is commented out. The password condition never runs, so I don't need to know any password.

The response returned the protected content, with the flag `bi0s{...}` in it. The login was bypassed entirely because the query authenticated the first matching row.

A note on process: there is nothing magic about this exact string. `' OR 1=1 -- ` and many variants do the same job, and curated lists (the kind you find in the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and payloadbox repositories) exist precisely so you can try several quickly. The skill is reading the error, forming a mental model of the query, and crafting input that makes it always-true while commenting out the rest.

## Defending against SQL injection

The fix is not escaping quotes or blocklisting keywords. It is to stop mixing code and data:

- **Use parameterised queries / prepared statements.** The query text and the parameters travel separately, so `' OR '1'='1` is only ever compared as a literal username and can never change the query's structure. This single change kills the entire bug class.
- **Use an ORM or query builder** that parameterises under the hood, consistently.
- **Apply least privilege** to the database account, so an injection that does slip through can't read or alter unrelated tables.
- **Never store or compare passwords in plaintext.** A login that checks `password = '...'` in SQL is already a red flag; passwords should be salted and hashed, with the comparison done in application code.

## Takeaways

- **A SQL error on a quote is the tell.** It means your input is being parsed as part of the query.
- **`OR '1'='1'` makes the WHERE always true; a comment deletes the rest.** Together they bypass the password check without any credentials.
- **Parameterised queries are the fix, not input filtering.** Separating code from data removes the vulnerability instead of trying to sanitise around it.

*Worked example: "secretkeeper", DD CTF by team bi0s. Flag redacted as `bi0s{...}`.*
