---
title: "Solving Classical and Homebrew Ciphers"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "Most CTF cipher challenges come down to a few ideas: modular arithmetic, substitution with a repeating key, reused XOR keystreams, and historical machines. This post covers how I identify which one I'm facing, then works through four challenges from the bi0s DD CTF: a modulo 'hash' that can be inverted, an Enigma message, a broken AES-CTR implementation, and a Vigenère cipher with an extended alphabet."
tags: ["cryptography", "ciphers", "ctf", "bi0s"]
categories: ["Cryptography"]
---

## Overview

CTF cipher challenges rarely use anything new. A challenge with a playful name usually hides one of a small set of techniques. It might be arithmetic that loses less information than it seems to, a classical polyalphabetic cipher, a modern primitive that has been wired up incorrectly, or a historical machine that only needs the right settings. Most of the work is figuring out which one you are looking at. After that, the solve is usually short.

This post is a reference guide to that process. I start with the questions I ask about any unknown ciphertext, then work through four challenges from the **DD CTF** run by team [bi0s](https://bi0s.in/):

1. **MOD**: each byte of the flag reduced modulo 97.
2. **Wojtek Enigma**: an Enigma machine message with the settings supplied.
3. **Treasure Count**: "AES-CTR" where the counter never changes, which turns it into repeating-key XOR over hex-encoded blocks.
4. **grandfather cipher**: a Vigenère cipher over a 38-character alphabet that includes digits and braces.

> **Scope and ethics.** These were educational challenges from a CTF that has since concluded, solved using the files the organisers distributed. Flags are redacted as `bi0s{...}`. Some of these challenges used a `flag{...}` or `FLAG{...}` format instead, and I mention that where the format itself is part of the technique.

## Approaching an unknown cipher

Before trying any tool, I answer a few questions about the ciphertext and whatever comes with it.

**1. Is there source code?** If the challenge gives you the encryption script, read that first. Homebrew ciphers are almost always broken by one specific line, such as a modulus that is too large or a counter that never increments. Finding that line beats any amount of guessing.

**2. What is the alphabet?** The set of characters in the ciphertext narrows things down quickly:

| What you see | Likely starting point |
|---|---|
| Only `A-Z`, word lengths preserved | Monoalphabetic substitution, Caesar/ROT, Atbash |
| Only `A-Z`, flat letter frequencies | Polyalphabetic (Vigenère and friends) or a rotor machine |
| `A-Z` plus digits/symbols, flag-shaped structure intact | Classical cipher over an extended alphabet |
| `0-9a-f`, even length | Hex-encoded bytes, often XOR or a block cipher underneath |
| `A-Za-z0-9+/=` | Base64 encoding (an encoding, not a cipher) |
| A list of small integers | Arithmetic on character codes |

**3. Does the structure survive?** If braces, underscores, or the flag prefix's length show through in the ciphertext, the cipher probably works character by character and passes some characters through unchanged. That makes a **crib** (known plaintext) attack possible.

**4. What plaintext do I already know?** This is the most useful question in CTF crypto. The flag format (`flag{`, `FLAG{`, `bi0s{`) gives you known plaintext at a known position. So do file signatures, such as the 8-byte PNG header. Against anything that combines plaintext with a key using addition or XOR, known plaintext reveals the key directly.

For the mechanics I rely on a few tools. [CyberChef](https://gchq.github.io/CyberChef/) is good for chaining decodings such as From Hex, XOR, and Base64, and its "Magic" operation can guess encodings. [dCode](https://www.dcode.fr/) has a cipher identifier and solvers for nearly every classical cipher, including Kasiski and index-of-coincidence analysis. [cryptii](https://cryptii.com/) has a configurable Enigma simulator. For anything homebrew, I reach for a few lines of Python, because it shows exactly what is happening.

## Challenge 1: MOD

### The setup

The challenge gave the encryption code and its output:

```python
flag = "#######redacted#######"
flag = flag.encode()
l = [i % 97 for i in flag]
print(l)
```

```text
[5, 11, 0, 6, 26, 77, 48, 3, 20, 49, 48, 95, 12, 52, 10, 51, 18, 95, 55, 7, 8, 13, 6, 18, 95, 11, 48, 48, 15, 28]
```

Each byte of the flag is replaced by its remainder modulo 97. In general, a modulo operation loses information. `15 % 12` and `27 % 12` are both `3`, so you cannot tell from the `3` which number you started with. The question is whether that loss actually matters here.

### Why it is invertible

It doesn't, because of the input range. A flag is printable ASCII, which runs from 32 (space) to 126 (`~`). That is 95 possible values. The modulus is 97. Two printable characters can only collide if they differ by a multiple of 97, and no two values in a window of 95 consecutive integers can do that. So **every residue maps back to at most one printable character**:

- Residues 32 to 96 come from characters 32 to 96 unchanged (`i % 97 == i`).
- Residues 0 to 29 come from characters 97 to 126 (`a` to `~`), which wrapped around once.
- Residues 30, 31, and 97 and above cannot come from printable input at all.

The output confirms this. The first four values, `5, 11, 0, 6`, are `102, 108, 97, 103` minus 97, which spells `flag`. The fifth, `26`, is `123 - 97`, which is `{`. The whole `flag{...}` wrapper is inside the list.

The general lesson: **reduction modulo m is a bijection on any range narrower than m**. A modulus only hides information when the inputs span more than one full cycle.

### Solving it

Brute-forcing each position over the printable range is the simplest approach. I also make the script check that each residue has exactly one candidate, so it fails loudly if the uniqueness argument ever doesn't hold:

```python
residues = [5, 11, 0, 6, 26, 77, 48, 3, 20, 49, 48, 95, 12, 52, 10,
            51, 18, 95, 55, 7, 8, 13, 6, 18, 95, 11, 48, 48, 15, 28]

PRINTABLE = range(32, 127)

def invert(r, m=97):
    candidates = [c for c in PRINTABLE if c % m == r]
    if len(candidates) != 1:
        raise ValueError(f"residue {r} has {len(candidates)} printable preimages")
    return chr(candidates[0])

print("".join(invert(r) for r in residues))
```

Every residue has exactly one preimage, and the script prints the full flag, `flag{` wrapper included (redacted here as `bi0s{...}`). Because the list already contains the wrapper, wrapping the output in `flag{...}` again is a mistake.

## Challenge 2: Wojtek Enigma

This challenge needed the least analysis, because `chall.txt` supplied both the ciphertext and the complete machine configuration. The only job was to configure a faithful simulator correctly.

Some background on why that is enough. An Enigma message is only secret if you don't know the **settings**: the machine model, which reflector and rotors are fitted and in what order, each rotor's ring setting and starting position, and the plugboard pairs. With those settings, decryption is mechanical. Enigma is also **reciprocal**: the reflector sends the signal back through the rotors, so a machine set up the same way that encrypted a message will decrypt it. You type the ciphertext in and the plaintext comes out.

I entered the settings from `chall.txt` into [cryptii's Enigma machine](https://cryptii.com/pipes/enigma-machine). One option matters a lot for CTFs: **foreign characters must be set to "include"**. A real Enigma only has the letters A to Z, so simulators either drop everything else or pass it through unchanged. A flag's braces and underscores are outside that alphabet. If the simulator strips them, the output loses its structure and is much harder to recognise as the flag. With foreign characters included, the flag came out in the right format.

My notes for this one only cover the tool and that option, not the exact rotor and plugboard values, so I'm not reproducing them here. The general takeaway: when a challenge gives you a machine's full key, the difficulty is in transcribing the settings correctly, not in cryptanalysis. A common mistake is to confuse ring settings (*Ringstellung*) with starting positions (*Grundstellung*).

## Challenge 3: Treasure Count

### What the code actually does

The description said this challenge used AES in CTR mode, with a hint that the target was a file called `flag.png`. It came with an encryption script (`chall.py`) and a text file of hex blocks (`chall.txt`).

Proper CTR mode turns a block cipher into a stream cipher. It encrypts a counter block (nonce plus block index) with AES to produce 16 bytes of keystream, XORs that keystream into 16 bytes of plaintext, then **increments the counter** for the next block. Because the counter is different for every block, every keystream block is different.

The script built CTR mode by hand. It encrypted a 16-byte counter with AES in ECB mode and XORed the result into the plaintext, which is exactly how CTR works internally. The flaw was that its custom counter **never incremented**. The same random initial 16 bytes were used for every block. So every block was XORed with the *same* 16-byte keystream:

```text
C_i = P_i XOR AES_k(counter)      for every block i
    = P_i XOR K                   where K is one fixed 16-byte value
```

The AES key doesn't matter any more. The "AES-CTR" encryption has become **repeating-key XOR with a 16-byte key**, and anyone who learns `K` can decrypt every block without touching AES. This is the same failure as reusing a nonce in any stream cipher: keystream reuse turns a strong cipher into a many-time pad.

### Recovering the keystream with a file-signature crib

XOR is its own inverse, so known plaintext gives the keystream directly: `K = C XOR P`. The hint about `flag.png` supplies the known plaintext, because every PNG starts with the same bytes. The 8-byte signature is always `89 50 4E 47 0D 0A 1A 0A`.

The first 8 bytes of `chall.txt` were `ea962e522997ca34`. XORing them with the signature gives the first half of the keystream:

```python
known = bytes.fromhex("89504e470d0a1a0a")   # PNG signature
enc   = bytes.fromhex("ea962e522997ca34")   # first 8 bytes of chall.txt
print(bytes(p ^ c for p, c in zip(known, enc)).hex())
# 63c66015249dd03e
```

A keystream block is 16 bytes, so 8 known bytes only cover half of it. My notes record the derivation of the first half. The full key I used was `63c66015249dd03e86317a67dbcb0294`. The natural way to get the second half is to extend the crib. In every PNG, the signature is followed by the IHDR chunk's length and type, which are also fixed: `00 00 00 0D 49 48 44 52`. That makes the entire first 16 bytes of the file known plaintext, enough for one full keystream block. (I cover these PNG constants in my post on [repairing corrupted PNG files](/posts/repairing-corrupted-png-files/).)

### Decrypting the file

`chall.txt` stores each 16-byte ciphertext block as 32 hex characters. Decryption means joining the hex, decoding it to bytes, and XORing with the keystream repeated over the whole file:

```python
from itertools import cycle

# PNG signature + IHDR length + "IHDR": the first 16 bytes of every PNG
PNG_HEAD = bytes.fromhex("89504e470d0a1a0a" "0000000d49484452")

with open("chall.txt") as f:
    ciphertext = bytes.fromhex("".join(f.read().split()))

keystream = bytes(c ^ p for c, p in zip(ciphertext[:16], PNG_HEAD))
plaintext = bytes(c ^ k for c, k in zip(ciphertext, cycle(keystream)))

with open("flag.png", "wb") as f:
    f.write(plaintext)
```

Removing all whitespace before calling `bytes.fromhex` handles newlines between blocks, which a fixed 32-character slicing approach would get wrong. The output opened as a valid PNG containing the flag (redacted as `bi0s{...}`). If the keystream had been wrong, the file would have failed its very first check, so `pngcheck` or simply opening the image is a quick way to verify the result.

## Challenge 4: grandfather cipher

### Identifying it

The challenge listed "Vigenère cipher" and "Kasiski test" as resources, so the cipher family was not in doubt. The twist was visible in the ciphertext:

```text
O8Q2HZE9PCID38QDRL3COL7C3ZS01DVEU8CX01Q6R{WDQ1}4P13001S4Y4UH6W
```

It contains digits and braces, so the alphabet is not just A to Z. The alphabet was:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}
```

That is 38 symbols, so all arithmetic is modulo 38 rather than 26. Each symbol's value is its index in this string. Vigenère encryption adds the key value to the plaintext value, and decryption subtracts it:

```text
C_i = (P_i + K_(i mod L)) mod 38
P_i = (C_i - K_(i mod L)) mod 38
```

A standard 26-letter solver either rejects these characters or skips them and gets out of step with the key. **Getting the alphabet exactly right, including its order, is the whole challenge.**

### Key length and the crib

The textbook first step against Vigenère is to estimate the key length `L`. The **Kasiski examination** looks for repeated sequences in the ciphertext. The same plaintext encrypted at the same key offset produces the same ciphertext, so the distances between repeats tend to be multiples of `L`. I ran dCode's Kasiski test, which suggested a length of 5.

The flag format is a stronger source of information. The plaintext must start with `FLAG{`, so rearranging the decryption formula gives the first five key characters directly: `K_i = (C_i - P_i) mod 38`.

```python
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"
IDX = {ch: i for i, ch in enumerate(ALPHABET)}

ciphertext = "O8Q2HZE9PCID38QDRL3COL7C3ZS01DVEU8CX01Q6R{WDQ1}4P13001S4Y4UH6W"
crib = "FLAG{"

key_prefix = "".join(
    ALPHABET[(IDX[c] - IDX[p]) % len(ALPHABET)] for c, p in zip(ciphertext, crib)
)
print(key_prefix)   # JXQWJ
```

The recovered prefix is `JXQWJ`, and its fifth character repeats its first. That is the signature of a **4-character key, `JXQW`**, not a 5-character one. I confirmed this by trying both. Decrypting with `JXQWJ` repeated produces a correct `FLAG{` followed by garbage. Decrypting with `JXQW` repeated produces readable English all the way through.

So the Kasiski estimate was wrong here. That isn't surprising: a 62-character ciphertext has very few repeated sequences, and the statistical tests become unreliable on such short texts. **Whenever a crib is available, it overrides the statistics.** A crib at least as long as the key gives you the key outright. One a little longer, like this one, also reveals the period through the repetition.

### Decrypting

```python
def vigenere_decrypt(ciphertext, key, alphabet=ALPHABET):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return "".join(
        alphabet[(idx[c] - idx[key[i % len(key)]]) % n]
        for i, c in enumerate(ciphertext)
    )

print(vigenere_decrypt(ciphertext, "JXQW"))
```

This prints the flag in the challenge's `FLAG{...}` format (redacted here as `bi0s{...}`), a sentence congratulating you on breaking the Vigenère cipher, written in leetspeak.

## Takeaways

- **Read the source for the one broken line.** The homebrew challenges here each failed on a single detail: a modulus larger than the input range, and a counter that never incremented. Find that detail and the rest follows.
- **Check whether an operation really loses information.** Modulo, truncation, and hashing-like steps can only hide data when the inputs span more than their output range. Printable ASCII modulo 97 hides nothing.
- **Never reuse a keystream.** CTR mode and other stream ciphers are only secure if each keystream block is used once. With a fixed counter, AES-CTR degrades to repeating-key XOR, and a single known file header breaks it.
- **Cribs beat statistics.** Flag prefixes and file signatures are free known plaintext. They recover XOR and Vigenère keys directly, and they can catch a wrong key-length estimate from Kasiski or index-of-coincidence analysis.
- **Match the alphabet and the tool settings exactly.** An extended Vigenère alphabet, or an Enigma simulator that drops braces, will produce near-misses that look like failure even though the method is right.

*Tools: Python, CyberChef, dCode (Kasiski examination), cryptii (Enigma simulator). Challenges: "MOD", "Wojtek Enigma", "Treasure Count", and "grandfather cipher", DD CTF by team bi0s.*
