---
title: "Enumerating a Server Through an Exposed Command Interface"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "When a web app hands you the ability to run shell commands, the challenge isn't getting code execution, it's knowing how to look around. Here I cover methodical filesystem enumeration from a command primitive, including seeing past a decoy flag to a hidden one, and why exposing command execution is total compromise."
tags: ["web-security", "command-execution", "enumeration", "ctf", "bi0s"]
categories: ["Web Security"]
---

## Overview

Some vulnerabilities give you the ability to run operating-system commands on the server, whether through command injection, an exposed admin feature, or, as in this challenge, a web app that is literally a command runner. Once you have that primitive, the work shifts from *getting* execution to *using* it well: orienting yourself on the filesystem and finding what you're after without thrashing.

This post uses the "shellshocker" challenge from the **DD CTF** (a concluded, educational CTF by team [bi0s](https://bi0s.in/)), a site that runs commands you submit as if at a bash prompt. It's a good vehicle for the enumeration habits that apply any time you land command execution.

> **Scope and ethics.** The target was a deliberately vulnerable CTF application that has since been retired. Running commands on a server you don't own or have permission to test is unauthorised access. Only do this in environments made available for it.

## Orienting yourself

With any command primitive, the first questions are always "where am I?" and "what's here?":

```bash
pwd       # where am I in the filesystem
ls -la    # what's in this directory, including hidden entries
cd ..     # move up and look again
```

The current directory held nothing useful, so I moved up a level and listed again. That turned up a file named like a flag. Printing it:

```bash
cat ../flag.txt
```

returned a value that was clearly a decoy, not a real flag. This is a common bit of misdirection in CTF challenges, and it's a useful reminder in real enumeration too: the first thing you find with the expected name isn't necessarily the thing you want.

## Searching instead of guessing

Rather than keep climbing directories by hand, I searched the filesystem for anything flag-like:

```bash
find / -type f -name "*flag*" 2>/dev/null
```

`find` walks the tree from `/`, matching any filename containing `flag`, and `2>/dev/null` discards the permission-denied noise so the real results stand out. The output listed several candidates, and one of them was a hidden file named `../.realflag` (the leading dot keeps it out of a plain `ls`). Printing that file gave the genuine flag, `bi0s{...}`.

The habit here is worth stating: when you don't know where something is, don't guess directory by directory, ask the system to find it. `find`, `grep -r`, and `locate` turn a search space you can't see into a list.

## Why this is total compromise

It's easy to treat "it's just a command box" as low severity because the challenge frames it playfully, but command execution on the server is the most serious outcome in web security. The same primitive that `cat`s a flag can read application source and secrets, dump environment variables and database credentials, pivot to internal services, or establish persistence. There is no "small" RCE.

## Defending against it

- **Never expose OS command execution to users.** If a feature needs to perform an operation, call a specific, constrained API for it, not a shell.
- **Avoid shells entirely in code.** Use language-native libraries instead of shelling out. Where a subprocess is unavoidable, pass arguments as a list (no shell interpolation) and never build a command string from user input.
- **Confine the process.** Run the web service as an unprivileged user, in a container or sandbox, with a read-only filesystem and no access to secrets it doesn't need, so that execution, if it ever happens, is contained.

## Takeaways

- **With a command primitive, enumeration is the skill.** `pwd`, `ls -la`, `cd ..`, then `find` beats guessing.
- **Distrust the obvious find.** A conveniently named flag can be a decoy; hidden dotfiles hide the real one.
- **RCE is game over.** Treat any path to command execution as critical and design so users never get one.

*Worked example: "shellshocker", DD CTF by team bi0s. Flag redacted as `bi0s{...}`.*
