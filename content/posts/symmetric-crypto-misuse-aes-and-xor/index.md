---
title: "When Symmetric Crypto Goes Wrong: AES Key-as-IV and XOR Mistakes"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "AES is not broken, but code that uses it often is. Here I explain why reusing the key as the CBC initialisation vector can hand an attacker the key itself, and why home-made XOR ciphers fall to known plaintext and key reuse. Each mistake comes with a working Python demonstration, the correct pattern, and a worked example from the bi0s DD CTF."
tags: ["cryptography", "aes", "xor", "ctf", "bi0s"]
categories: ["Cryptography"]
---

## Overview

Modern symmetric ciphers are extremely strong. Nobody breaks AES-128 by attacking the cipher itself. When encrypted data gets recovered in practice, it is almost always because of how the cipher was *used*: a predictable or reused IV, a missing integrity check, a key in the wrong place, or a "simple" custom cipher built from XOR. Those mistakes are easy to make and they cost the attacker very little effort.

This post is a reference guide to two families of mistakes:

1. **AES-CBC with the key reused as the IV.** I explain why an initialisation vector must be random and independent of the key, and show two ways the key can leak when it is not: from a single known plaintext block, and from a single query to a decryption oracle.
2. **XOR "encryption".** I cover the properties that make XOR useful as a building block, and why those same properties make a bare XOR cipher trivial to break with known plaintext or a reused key.

For each mistake I show the reasoning, a self-contained Python demonstration, and the defensive fix. The worked examples come from three challenges in the **DD CTF** run by team [bi0s](https://bi0s.in/): *flawless AES*, *XOR bash*, and *Decrypt the secrets*.

All the code uses Python 3 and [PyCryptodome](https://www.pycryptodome.org/) (`pip install pycryptodome`), which provides the `Crypto.Cipher.AES` API used below.

> **Scope and ethics.** The challenges were educational files from a CTF that has since concluded, and I worked on local copies distributed for that purpose. The demonstrations generate their own keys and data. The point of showing the attacks is to make clear why the defensive patterns exist. Flags are redacted as `bi0s{...}`.

## Background: how CBC uses the IV

AES is a **block cipher**. On its own it maps one 16-byte block to another under a key: `E_K(block)` to encrypt and `D_K(block)` to decrypt. To encrypt longer messages you need a **mode of operation**, and one of the most common is **CBC (Cipher Block Chaining)**. CBC XORs each plaintext block with the previous ciphertext block before encrypting it. The first block has no previous ciphertext, so it is XORed with the **initialisation vector (IV)** instead:

```text
Encryption:   C1 = E_K(P1 ⊕ IV)         Ci = E_K(Pi ⊕ C(i-1))
Decryption:   P1 = D_K(C1) ⊕ IV         Pi = D_K(Ci) ⊕ C(i-1)
```

Two properties of the IV matter for everything that follows:

- **The IV is not secret.** It is needed for decryption, so it is normally sent in the clear, usually prepended to the ciphertext. Anything you put in the IV slot should be assumed public.
- **The IV must be unpredictable and fresh for every message.** CBC's security proof assumes a random IV. If the IV is fixed, encrypting the same plaintext twice produces the same ciphertext, and messages that share a prefix produce ciphertexts that share a prefix, which leaks information without any key recovery at all.

Using the key as the IV violates both: it puts a secret into a public parameter, and it makes the IV constant.

## Mistake 1: using the key as the IV

### Why developers do it

The mistake usually comes from a reasonable-sounding thought: "the API wants a 16-byte key and a 16-byte IV, I already have one secret 16-byte value, and both sides know it, so I don't need to transmit the IV." It removes a field from the message format and appears to work perfectly, because encryption and decryption still round-trip. Nothing fails until someone attacks it.

### Leak 1: one known plaintext block reveals the key (flawless AES)

In *flawless AES*, the challenge script encrypted two things and wrote both results to an output file: a message whose opening text was known (`This is top secret`), and the flag. The vulnerability was that the secret key was passed in the **IV position** when encrypting the known message, while the value used as the AES key for that message was `iv1`, which was written to the output file. The same secret key was then used, correctly placed, to encrypt the flag.

Reduced to the lines that matter, the pattern looks like this. This is a minimal reconstruction for illustration, not the original challenge script:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)     # the real secret
iv1 = get_random_bytes(16)
iv2 = get_random_bytes(16)

# BUG: the secret key is passed as the IV, and iv1 (which gets published) is used as the key
ct1 = AES.new(iv1, AES.MODE_CBC, iv=key).encrypt(pad(b"This is top secret", 16))

# The flag is encrypted correctly, but with the same secret key
ct2 = AES.new(key, AES.MODE_CBC, iv=iv2).encrypt(pad(b"bi0s{...}", 16))

# Output layout: iv1 | first block of ct1 | iv2 | ct2
with open("encrypted", "wb") as f:
    f.write(iv1 + ct1[:16] + iv2 + ct2)
```

Apply the CBC equation to the first block of the known message. Its AES key is `iv1` and its IV is the secret `key`:

```text
C1 = E_iv1(P1 ⊕ key)
D_iv1(C1) = P1 ⊕ key
key = D_iv1(C1) ⊕ P1
```

Everything on the right-hand side is available to the attacker. `iv1` and `C1` are in the output file, and `P1` is the first 16 bytes of the known message. Decrypting one block with AES in ECB mode (a single raw block operation with no chaining) gives `P1 ⊕ key`, and XORing with the known plaintext removes `P1` and leaves the key. The secret was never really protected: it was used as a one-time pad over a block the attacker could already read.

Here is my solve script, cleaned up:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BLOCK = 16
KNOWN_FIRST_BLOCK = b"This is top secret"[:BLOCK]   # only the first 16 bytes are needed

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

with open("encrypted", "rb") as f:
    iv1 = f.read(BLOCK)          # used as the AES key for the known message
    ct1_block1 = f.read(BLOCK)   # first ciphertext block of the known message
    iv2 = f.read(BLOCK)          # the real IV for the flag
    ct2 = f.read()               # the encrypted flag

# Undo the block cipher on C1 without the CBC XOR step. This yields P1 XOR key.
p1_xor_key = AES.new(iv1, AES.MODE_ECB).decrypt(ct1_block1)

# Remove the known plaintext to isolate the key.
key = xor(p1_xor_key, KNOWN_FIRST_BLOCK)

# Decrypt the flag normally and strip the PKCS#7 padding.
flag = unpad(AES.new(key, AES.MODE_CBC, iv=iv2).decrypt(ct2), BLOCK)
print(flag)   # bi0s{...}
```

The `unpad` call matters. The flag is not a multiple of 16 bytes long, so it was padded before encryption, and printing the raw decryption shows trailing padding bytes rather than a clean flag.

### Leak 2: the textbook attack with a decryption oracle

The CTF version needed a known plaintext block. The more common real-world form of this bug is `AES.new(key, AES.MODE_CBC, iv=key)`, with the same value in both slots. In that case the key can be recovered with **no known plaintext at all**, as long as the attacker can submit a ciphertext and see what it decrypts to. That access is called a decryption oracle. It sounds like a strong requirement, but an error message such as `invalid input: <decrypted bytes>` is enough.

The attacker takes any valid ciphertext of three or more blocks and replaces its first three blocks with `C1 || 0 || C1`, where `0` is a block of zero bytes. With `IV = K`, decryption gives:

```text
P'1 = D_K(C1) ⊕ IV = D_K(C1) ⊕ K
P'2 = D_K(0)  ⊕ C1              (garbage, ignored)
P'3 = D_K(C1) ⊕ 0  = D_K(C1)

P'1 ⊕ P'3 = K
```

The zero block cancels the chaining for the third block, so `P'3` is the raw block decryption of `C1`. The first block is the same value XORed with the key. One query and one XOR give the key:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

BLOCK = 16
SECRET_KEY = get_random_bytes(BLOCK)

class InvalidInput(Exception):
    """Raised by the server; it unwisely includes the decrypted bytes."""
    def __init__(self, plaintext: bytes):
        super().__init__("message contains non-ASCII bytes")
        self.plaintext = plaintext

def encrypt(plaintext: bytes) -> bytes:
    # The vulnerable pattern: key and IV are the same value
    return AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY).encrypt(pad(plaintext, BLOCK))

def decryption_oracle(ciphertext: bytes) -> None:
    plaintext = AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY).decrypt(ciphertext)
    if not plaintext.isascii():
        raise InvalidInput(plaintext)   # the leak: error echoes the decryption

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# --- attacker side: holds one ciphertext and can call the oracle ---
ct = encrypt(b"comment1=cooking;userdata=hello;comment2=like a pound of bacon")
c1 = ct[:BLOCK]
forged = c1 + bytes(BLOCK) + c1 + ct[3 * BLOCK:]

try:
    decryption_oracle(forged)
except InvalidInput as err:
    p1 = err.plaintext[:BLOCK]
    p3 = err.plaintext[2 * BLOCK:3 * BLOCK]
    recovered = xor(p1, p3)
    print("key recovered:", recovered == SECRET_KEY)   # True
```

This is the same attack as challenge 27 of the [Cryptopals](https://cryptopals.com/sets/4/challenges/27) exercises. Once the key is known, the attacker can decrypt all past traffic and forge new messages.

### The fix: random IVs, and preferably authenticated encryption

The minimum fix is to generate a fresh random IV for every message and send it with the ciphertext:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)                    # new, unpredictable, never derived from the key
    return iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(plaintext, 16))

def cbc_decrypt(key: bytes, blob: bytes) -> bytes:
    iv, ciphertext = blob[:16], blob[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), 16)
```

That stops the key from leaking, but plain CBC still has no **integrity**. An attacker can flip bits in the IV or in a ciphertext block to make predictable changes to the decrypted plaintext. If the server reveals whether padding was valid, that is the classic padding oracle attack, which decrypts messages without the key. Both the oracle attack above and padding oracles depend on the server decrypting attacker-modified ciphertext and reacting to the result.

The better fix is **authenticated encryption**, such as AES-GCM. GCM encrypts and also computes an authentication tag over the ciphertext and any associated data. If a single bit is altered, decryption fails before any plaintext is released:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE_SIZE = 12   # 96-bit nonce, the recommended size for GCM
TAG_SIZE = 16

def gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = get_random_bytes(NONCE_SIZE)          # must never repeat under the same key
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)                             # authenticated but not encrypted (headers, IDs)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

def gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:-TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)   # raises ValueError if anything was modified

key = get_random_bytes(32)                         # AES-256 key from a CSPRNG
blob = gcm_encrypt(key, b"attack at dawn", aad=b"msg-id:42")
print(gcm_decrypt(key, blob, aad=b"msg-id:42"))    # b'attack at dawn'

tampered = bytearray(blob)
tampered[NONCE_SIZE] ^= 0x01                       # flip one ciphertext bit
try:
    gcm_decrypt(key, bytes(tampered), aad=b"msg-id:42")
except ValueError as err:
    print("rejected:", err)                        # rejected: MAC check failed
```

GCM has its own strict rule: **a nonce must never be reused with the same key**. Reusing one leaks the XOR of the two plaintexts (the keystream problem described in the next section) and allows tag forgery. Random 96-bit nonces are fine for a moderate number of messages per key. For very high volumes, use a counter-based nonce or rotate keys.

**Defensive takeaway:** the key and the IV or nonce are different things with different jobs. The key is secret and long-lived. The IV or nonce is public and must be unique for each message. Generate IVs and nonces with a CSPRNG (`get_random_bytes`, or `secrets` / `os.urandom`), never derive them from the key, and use an AEAD mode like AES-GCM or ChaCha20-Poly1305 so that tampered ciphertexts are rejected instead of decrypted.

## Mistake 2: treating XOR as encryption

### XOR fundamentals

XOR (`^` in Python) compares two bits and outputs 1 when they differ. Applied byte by byte, it has four properties that make it central to cryptography:

| Property | Identity | Consequence |
|---|---|---|
| Self-inverse | `a ^ a = 0` | Anything XORed with itself cancels out |
| Identity | `a ^ 0 = a` | XORing with zero changes nothing |
| Commutative and associative | `a ^ b = b ^ a` | Order and grouping don't matter |
| Reversible | `a ^ b ^ b = a` | The same operation encrypts and decrypts |

The last row is why XOR appears inside almost every cipher. Stream ciphers and modes like CTR and GCM generate a pseudorandom **keystream** and XOR it with the plaintext. Decryption is the same XOR. That is also exactly the problem with using XOR *on its own*. The operation adds no secrecy. All of the security comes from the keystream being unpredictable, as long as the message, and never reused. A short repeating key provides none of those guarantees.

A typical home-made "XOR cipher" repeats a short key across the message:

```python
from itertools import cycle

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR. Encryption and decryption are the same function."""
    return bytes(d ^ k for d, k in zip(data, cycle(key)))

a, b = 0b1011_0110, 0b0101_1100
assert a ^ b ^ b == a       # reversibility
assert a ^ a == 0           # self-inverse
assert a ^ 0 == a           # identity
```

### Weakness 1: known plaintext gives you the key

Because `ciphertext = plaintext ^ key`, rearranging gives `key = ciphertext ^ plaintext`. Anyone who knows or can guess part of the plaintext recovers that part of the key immediately. Known plaintext is almost always available: file headers (`%PDF-`, `\x89PNG`), protocol greetings, JSON braces, or, in a CTF, the flag format.

```python
from itertools import cycle

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))

key = b"s3cr3tk3y"                                     # the defender's 9-byte secret
ciphertext = xor_bytes(b"bi0s{this_is_a_made_up_example_flag}", key)

# The attacker only knows that flags start with "bi0s{"
crib = b"bi0s{"
print(xor_bytes(ciphertext[:len(crib)], crib))         # b's3cr3': the first 5 key bytes

# With a known prefix at least as long as the key, the whole key falls out
msg = b"Hello Bob, the meeting is moved to 9pm"
ciphertext = xor_bytes(msg, key)
recovered = bytes(c ^ p for c, p in zip(ciphertext, b"Hello Bob"))
print(recovered, xor_bytes(ciphertext, recovered))     # b's3cr3tk3y' and the full message
```

Because the key repeats, recovering one key-length of it decrypts the entire message. Even with no known plaintext, a repeating key can be broken statistically. The attacker estimates the key length from Hamming distances between ciphertext chunks, then solves each key byte as an independent single-byte XOR using English letter frequencies.

XOR with a key byte also leaks structure directly. Wherever a plaintext byte equals the key byte at that position, the ciphertext byte is `0x00`. Wherever two plaintext bytes that share a key position are equal, their ciphertext bytes are equal too.

### Weakness 2: key reuse cancels the key

Even a perfectly random key, the one-time pad, fails if it is used twice. XOR the two ciphertexts together and the key disappears:

```text
C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

The attacker now has the XOR of two plaintexts with no key involved. If either message is known, the other follows. If neither is known, guessing likely words at each offset ("crib dragging") recovers both, because natural language is highly redundant.

```python
from itertools import cycle

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))

key = b"s3cr3tk3y"
c1 = xor_bytes(b"transfer 100 to alice", key)
c2 = xor_bytes(b"meet me at the docks!", key)

p1_xor_p2 = xor_bytes(c1, c2)                         # the key has cancelled out
print(xor_bytes(p1_xor_p2, b"transfer 100 to alice")) # b'meet me at the docks!'
```

This is the same failure as nonce reuse in AES-CTR or AES-GCM. Those modes are keystream XOR internally, so the same key and nonce produce the same keystream, and two ciphertexts under it combine into `P1 ⊕ P2`.

### Worked example: XOR bash

*XOR bash* provided the encryption script and a base64 output string, `HQYQMAAAHTAAAgYADAc=`. The script applied two layers:

1. A substitution it called an "affine cipher": each letter is replaced by its mirror in the alphabet (`a`↔`z`, `b`↔`y`, and so on), while underscores and other characters pass through. This is **Atbash**, which is the affine cipher `E(x) = 25x + 25 mod 26`. It has no key, and it is its own inverse.
2. A repeating-key XOR with the key `zoro`, followed by base64.

None of these layers adds real security. Base64 is an encoding, not encryption. Atbash has no key at all. The XOR key was a 4-byte dictionary word, and it was printed in the source. Stacking weak transformations does not produce a strong one: each layer is independently reversible, so the attacker just undoes them in reverse order.

The ciphertext also shows the structural leak described above. Decoding it shows that four of its fourteen bytes are `0x00`:

```text
1d 06 10 30 00 00 1d 30 00 02 06 00 0c 07
            ^^ ^^       ^^       ^^
```

At each of those offsets, the Atbash-encoded character is identical to the key character at that position. Even without the source, that is a strong hint about both the key and the plaintext.

Reversing the layers in order (base64 decode, XOR, Atbash):

```python
import base64
from itertools import cycle

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, cycle(key)))

def atbash(text: str) -> str:
    """Mirror a-z (a<->z, b<->y, ...). Applying it twice returns the original."""
    out = []
    for ch in text.lower():
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            out.append(ch)               # underscores and other characters pass through
    return "".join(out)

def xorbash_decrypt(b64_ciphertext: str, key: str) -> str:
    raw = base64.b64decode(b64_ciphertext)           # layer 3: undo base64
    atbashed = xor_bytes(raw, key.encode()).decode() # layer 2: XOR is its own inverse
    return atbash(atbashed)                          # layer 1: Atbash is its own inverse

print(xorbash_decrypt("HQYQMAAAHTAAAgYADAc=", "zoro"))   # a 14-character answer (redacted)
```

The output is a short underscore-separated phrase, which the challenge asked to be wrapped in its flag format. I've left it redacted here.

### Worked example: Decrypt the secrets

*Decrypt the secrets* was a small packet capture of 18 packets. Opening it in Wireshark showed that the traffic was an unencrypted ASCII conversation, so every message could be read directly from the packet bytes. One packet stood out: four characters followed by a `{...}` group, exactly the shape of `bi0s{...}`, but with different letters.

Strictly speaking, this was a **rotation (Caesar) cipher**, not XOR, but it fails for the same reasons. Letter-by-letter substitution preserves the structure of the plaintext: length, punctuation, digits, and the braces all survive. The flag format therefore acted as a crib, just like `bi0s{` in the XOR example. With only 25 possible keys, there is nothing to analyse: try every shift and keep the one that produces the known prefix. That is how I recovered the flag from that packet.

Here is the approach, demonstrated on a made-up string rather than the real flag:

```python
def rotate(text: str, shift: int) -> str:
    """Caesar-shift letters by `shift`, preserving case; leave digits and symbols alone."""
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)

ciphertext = "ov0f{rknzcyr_bayl}"     # illustrative only
for shift in range(26):
    candidate = rotate(ciphertext, -shift)
    if candidate.startswith("bi0s{"):  # the known flag format is the crib
        print(shift, candidate)        # 13 bi0s{example_only}
```

The bigger lesson from this challenge comes before the cipher. The conversation itself crossed the network in plaintext. Anyone with a packet capture could read it, so the cipher only protected one message, and it did that badly. Encryption in transit (TLS) should have been the baseline.

### The fix: don't roll your own

**Defensive takeaway:** never use XOR, substitution, or a stack of encodings as a cipher. If you need confidentiality, use a vetted AEAD construction from a maintained library, such as AES-GCM in PyCryptodome or the high-level [`cryptography`](https://cryptography.io/) package's `Fernet` and `AESGCM`. Generate keys with a CSPRNG and never hard-code them in source. Never reuse a key and nonce pair. Use TLS for data in transit instead of inventing a protocol. XOR belongs *inside* well-designed primitives, where the keystream is generated securely, not as the primitive itself.

## Takeaways

- **The IV is public; the key is secret.** Putting the key in the IV slot turns a public parameter into a key leak. One known plaintext block, or one decryption oracle query, is enough to recover it.
- **IVs and nonces must be random (or unique) for every message, and independent of the key.** Generate them with `get_random_bytes` and send them alongside the ciphertext.
- **Prefer authenticated encryption.** AES-GCM rejects modified ciphertexts before releasing any plaintext, which closes off the oracle-style attacks that unauthenticated CBC allows.
- **XOR is reversible, and that cuts both ways.** `ciphertext ^ plaintext = key`, so any known plaintext reveals the key, and `C1 ^ C2 = P1 ^ P2`, so any key reuse removes the key entirely.
- **Layers of weak transforms are still weak.** Base64, Atbash, Caesar shifts, and short-key XOR are each trivially reversible, and combining them only adds steps.

*Tools: Python 3, PyCryptodome, Wireshark. Challenges: "flawless AES", "XOR bash", and "Decrypt the secrets", DD CTF by team bi0s.*
