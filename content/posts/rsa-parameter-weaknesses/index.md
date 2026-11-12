---
title: "Common RSA Weaknesses: Shared Primes, Close Primes, and Bad Parameters"
date: 2026-11-12
lastmod: 2026-11-12
draft: false
summary: "RSA is only as strong as the primes behind it. If two keys share a prime, or if p and q sit too close together, the modulus can be factored in seconds with a GCD or Fermat's method. Here I explain the maths behind each weakness, with clean Python solves for four crypto challenges from the bi0s DD CTF."
tags: ["cryptography", "rsa", "ctf", "bi0s"]
categories: ["Cryptography"]
---

## Overview

RSA's security rests on a single assumption: given a public modulus `n = p * q`, nobody can recover `p` and `q`. For properly generated 2048-bit keys, that assumption holds. Nobody can factor them with known methods. But the assumption is about *properly generated* keys. If the primes are reused, related, or placed too close together, factoring stops being hard, and often takes nothing more than one line of Python.

This post is a reference guide to the most common of those mistakes. I start with a short recap of how RSA works, because every attack below ends the same way: recover the factors, rebuild the private key, decrypt. Then I go through each weakness with the maths behind it and a short solve script, using four crypto challenges from the **DD CTF** run by team [bi0s](https://bi0s.in/):

1. **Common Primes**: several public keys, two of which share a prime.
2. **Common Thread**: one modulus reused with two different public exponents.
3. **Too close for comfort**: `q` is simply the next prime after `p`.
4. **Is it RSA**: a multi-prime modulus built from reused and repeated primes.

Everything here uses standard Python 3.8+ integer arithmetic (`math.gcd`, `math.isqrt`, and three-argument `pow`). The challenges themselves used [PyCryptodome](https://pypi.org/project/pycryptodome/) to generate keys.

> **Scope and ethics.** These were educational challenges from a CTF that has since concluded, and the techniques are standard material in any university cryptography course. Everything was run locally against the challenge files the organisers distributed. Flags are redacted as `bi0s{...}`.

## RSA in five minutes

### Key generation

1. Pick two large random primes `p` and `q`, and compute the **modulus** `n = p * q`.
2. Compute Euler's totient `phi(n) = (p - 1) * (q - 1)`. This is the number of integers below `n` that are coprime to it.
3. Choose a **public exponent** `e` with `gcd(e, phi(n)) = 1`. In practice this is almost always `65537`.
4. Compute the **private exponent** `d = e^-1 mod phi(n)`, the number for which `e * d ≡ 1 (mod phi(n))`.

The public key is `(n, e)`. The private key is `d`, and `p`, `q`, and `phi(n)` must stay secret too, because any one of them leads straight to `d`.

### Encryption and decryption

A message is turned into an integer `m < n` (by reading its bytes as one big-endian number), then:

```text
encrypt:  c = m^e mod n
decrypt:  m = c^d mod n
```

Decryption works because `e * d = 1 + k * phi(n)` for some integer `k`, and Euler's theorem says `m^phi(n) ≡ 1 (mod n)` when `m` is coprime to `n`. So `c^d = m^(e*d) = m * (m^phi(n))^k ≡ m (mod n)`.

### Why the factors are everything

An attacker knows `n` and `e`. The only thing standing between them and `d` is `phi(n)`, and computing `phi(n)` requires knowing `p` and `q`. **Factoring `n` is equivalent to breaking the key.** Every weakness in this post is a shortcut to that factorisation.

Because of that, I use the same two helpers at the end of every solve. Python's `pow(e, -1, phi)` computes a modular inverse directly, and `int.to_bytes` does the job of PyCryptodome's `long_to_bytes`:

```python
def long_to_bytes(m: int) -> bytes:
    """Convert an integer back into its big-endian byte string."""
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def decrypt_with_factors(c: int, e: int, p: int, q: int) -> bytes:
    """Standard two-prime RSA decryption once p and q are known."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)          # modular inverse of e mod phi (Python 3.8+)
    return long_to_bytes(pow(c, d, n))
```

## Weakness 1: Two keys that share a prime

### The maths

Suppose two different public keys were generated with one prime in common:

```text
n1 = p * q1
n2 = p * q2
```

Factoring either modulus on its own is infeasible. But I don't need to factor either one. The greatest common divisor of the two moduli is exactly the shared prime:

```text
gcd(n1, n2) = p
q1 = n1 / p
q2 = n2 / p
```

Euclid's algorithm computes a GCD in a number of steps proportional to the bit length of the inputs, so this takes microseconds even for 4096-bit moduli. One GCD factors **both** keys.

This is not just a CTF curiosity. In 2012, two research teams independently collected millions of RSA public keys from the internet (TLS certificates, SSH host keys, PGP keys) and computed GCDs across them. They found many keys that shared primes and factored them instantly ([Mining Your Ps and Qs](https://factorable.net/) by Heninger et al., and "Ron was wrong, Whit is right" by Lenstra et al.). The root cause was mostly embedded devices generating keys at first boot, before their random number generators had gathered enough entropy, so different devices ended up picking the same "random" primes.

### Challenge: Common Primes

The challenge handed out four public moduli, all using `e = 65537`, and four ciphertexts. The description hinted that two of the keys might share a prime. With four keys there are only six pairs to check, so I just tried them all:

```python
from itertools import combinations
from math import gcd

e = 65537
moduli = [...]        # the four public moduli from the challenge output
ciphertexts = [...]   # the matching ciphertexts, in the same order


def find_shared_prime(moduli):
    """Return (i, j, p) for the first pair of moduli that share a prime factor p."""
    for (i, ni), (j, nj) in combinations(enumerate(moduli), 2):
        p = gcd(ni, nj)
        if 1 < p < ni:            # p == ni would mean identical moduli, not a shared prime
            return i, j, p
    return None


i, j, p = find_shared_prime(moduli)
print(f"keys {i} and {j} share a {p.bit_length()}-bit prime")

for k in (i, j):
    q = moduli[k] // p            # the other factor falls out by division
    print(decrypt_with_factors(ciphertexts[k], e, p, q))
```

Once the shared prime is known, each key is ordinary RSA with known factors. The decrypted plaintext contains the flag (`bi0s{...}`).

For a large collection of keys, pairwise GCDs scale quadratically. The researchers above used a **batch GCD** algorithm (a product tree followed by a remainder tree) to test millions of keys against each other in a matter of hours. The principle is the same.

### Related mistake: reusing the whole modulus (Common Thread)

"Common Thread" looks like the same family but is a different bug. Here nothing is shared between two keys. Instead, **one** modulus `n` is reused with two public exponents, `e1 = 3` and `e2 = 65537`, and the *same* plaintext is encrypted under both:

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
```

No factoring is needed. Because `gcd(e1, e2) = 1`, the extended Euclidean algorithm finds integers `x` and `y` with `e1 * x + e2 * y = 1`. Then:

```text
c1^x * c2^y = m^(e1*x) * m^(e2*y) = m^(e1*x + e2*y) = m^1 = m  (mod n)
```

One of `x` or `y` is always negative (for these exponents, `x = 21846` and `y = -1`). A negative exponent means "raise the modular inverse of the ciphertext to the positive power". Python's three-argument `pow` handles that automatically, as long as the ciphertext is coprime to `n`:

```python
def extended_gcd(a: int, b: int):
    """Return (g, x, y) such that a*x + b*y == g == gcd(a, b)."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        quotient, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - quotient * x1
        y0, y1 = y1, y0 - quotient * y1
    return a, x0, y0


def common_modulus_attack(n, e1, c1, e2, c2) -> bytes:
    g, x, y = extended_gcd(e1, e2)
    if g != 1:
        raise ValueError("exponents must be coprime")
    # pow(c, negative, n) uses the modular inverse of c (Python 3.8+)
    m = pow(c1, x, n) * pow(c2, y, n) % n
    return long_to_bytes(m)


n = ...           # shared modulus from output.txt
ct1, ct2 = ...    # ciphertexts under e1 = 3 and e2 = 65537
print(common_modulus_attack(n, 3, ct1, 65537, ct2))
```

As a side note, this challenge had a second weakness. With `e1 = 3` and a short flag, `m^3` was smaller than `n`, so the modular reduction never happened and the integer cube root of `c1` was already the plaintext. Small exponents combined with short, unpadded messages are a separate classic mistake.

Reusing a modulus is broken even when the messages differ. Anyone who holds one valid `(e, d)` pair for `n` can use it to factor `n`, and then compute every other private exponent for that modulus. A modulus must belong to exactly one key pair.

### Defensive takeaway

- **Never reuse primes or moduli.** Every key pair needs its own freshly generated `p` and `q`, and every user or device needs its own modulus.
- **Generate primes from a properly seeded CSPRNG.** Shared primes in the real world came from low-entropy random number generators, not from deliberate reuse. Make sure the system has gathered enough entropy before generating long-term keys, especially on embedded devices at first boot.
- **Use a vetted library** (OpenSSL, Python's `cryptography` package, your platform's crypto API) rather than generating primes yourself, and always use proper padding (OAEP for encryption), which also defeats the cube-root shortcut.

## Weakness 2: Primes that are too close together

### The maths: Fermat's factorisation

Fermat noticed that any odd number can be written as a difference of two squares:

```text
n = a^2 - b^2 = (a - b) * (a + b)
```

For an RSA modulus with `p < q`, the matching values are:

```text
a = (p + q) / 2       (the midpoint of p and q)
b = (q - p) / 2       (half the gap between them)
```

Because `n = p * q`, the midpoint `a` is always a little larger than `sqrt(n)`. The method is to start at `a = ceil(sqrt(n))` and step upwards, checking each time whether `a^2 - n` is a perfect square. When it is, that square is `b^2`, and the factors are `a - b` and `a + b`.

How many steps does that take? The distance between the starting point and the true midpoint is:

```text
a - sqrt(n) = (p + q)/2 - sqrt(p*q) = (sqrt(q) - sqrt(p))^2 / 2 ≈ (q - p)^2 / (8 * sqrt(n))
```

The cost depends on the **square of the gap** between the primes, divided by roughly `sqrt(n)`. For two independent random 512-bit primes, the gap is typically around `2^510`, giving on the order of `2^505` steps. That will never finish. But if the gap is small compared to `n^(1/4)`, the very first candidate is already correct.

### Challenge: Too close for comfort

The challenge source gave the weakness away in two lines:

```python
p = getPrime(512)
q = next_prime(p)
```

`q` is the first prime after `p`. Primes near `2^512` are on average about `355` apart (roughly `ln(2^512)`), so `q - p` is tiny. I wrote Fermat's method like this:

```python
from math import isqrt


def fermat_factor(n: int, max_steps: int = 1_000_000):
    """Factor n = p*q when p and q are close together. Returns (p, q) or None."""
    if n % 2 == 0:
        return 2, n // 2
    a = isqrt(n)
    if a * a < n:                 # start at ceil(sqrt(n))
        a += 1
    for _ in range(max_steps):
        b_squared = a * a - n
        b = isqrt(b_squared)
        if b * b == b_squared:    # a^2 - n is a perfect square
            return a - b, a + b
        a += 1
    return None                   # primes are not close enough for this method


n = ...     # 1024-bit modulus from the challenge
c = ...     # encrypted flag
e = 65537

p, q = fermat_factor(n)
assert p * q == n
print(decrypt_with_factors(c, e, p, q))
```

On the challenge modulus, the gap between `p` and `q` was only `234`, so `ceil(sqrt(n))` was already the exact midpoint. The loop succeeded on the first check, and decryption with the recovered factors gave the flag text, which I wrapped in the flag format (`bi0s{...}`).

This weakness has also appeared in the real world. In 2022, Hanno Böck found [RSA keys in deployed printers and other devices](https://fermatattack.secvuln.info/) that Fermat's method could factor (CVE-2022-26320), because the key generator derived both primes from nearly the same starting point instead of choosing them independently.

### Defensive takeaway

- **Generate `p` and `q` independently**, each from fresh CSPRNG output. Never derive one prime from the other, for example with `next_prime(p)` or `p + small_offset`.
- **Check the distance.** NIST's FIPS 186 key-generation rules require `|p - q| > 2^(nlen/2 - 100)`. For a 2048-bit key, that means the primes must differ somewhere in their top 100 bits. Vetted libraries already enforce this, which is another reason to use them.

## Weakness 3: Recognising non-standard RSA (Is it RSA)

### What made it different

The last challenge was a reminder that RSA does not have to be two primes, and that the decryption maths generalises cleanly once you understand where `phi(n)` comes from. The challenge gave three moduli `n1`, `n2`, `n3`, one ciphertext `c` (encrypted under `n3`), and `e = 65537`. The source used four primes `p`, `q`, `r`, `s` instead of two.

Comparing bit lengths was the first clue. `n1` and `n2` were 2048 bits each (two 1024-bit primes), but `n3` was about 7165 bits, far too large to be a product of two primes. It had to be built from several.

### Step 1: a shared prime again

`n1 = p * q` and `n2 = q * r` shared the prime `q`, so Weakness 1 applied directly:

```text
q = gcd(n1, n2)
p = n1 / q
r = n2 / q
```

### Step 2: peeling the known primes off n3

My first attempt was to compute the leftover `s = n3 / (p * q * r)` and treat it as the fourth prime. The product check passed, but that leftover was **not prime**. Testing it with `gcd` against `p`, `q`, and `r` showed that it still contained some of them. Each time I divided one out, what remained was still composite, so I had to keep dividing. That repeated splitting is what the description's "elusive" factor `s` refers to.

The clean way to handle this is to divide out each known prime as many times as it goes in, counting multiplicities. When I did that, the structure became clear:

```text
n3 = p^3 * q * r^2 * s       (s is a fresh 1024-bit prime)
```

That is seven 1024-bit factors, which matches the 7165-bit size.

### Step 3: the generalised totient

Euler's totient is multiplicative over coprime factors, and for a prime power it is:

```text
phi(p^k) = p^(k-1) * (p - 1)
```

So for any factorisation `n = p1^k1 * p2^k2 * ...`:

```text
phi(n) = product of  p_i^(k_i - 1) * (p_i - 1)
```

For the standard two-prime case, every `k_i = 1`, and this collapses back to `(p - 1) * (q - 1)`. Everything else in RSA stays the same: `d = e^-1 mod phi(n)` and `m = c^d mod n`. Decryption still works with repeated factors as long as `m` is coprime to `n`, which is guaranteed here because the plaintext is smaller than every prime factor.

### The solve

```python
from collections import Counter
from math import gcd

from sympy import isprime        # only used to sanity-check the leftover factor

e = 65537
n1, n2, n3, c = ...              # values from the challenge output


def divide_out(n: int, primes):
    """Divide each known prime out of n as many times as possible.
    Returns (Counter of prime -> exponent, remaining cofactor)."""
    counts = Counter()
    for p in primes:
        while n % p == 0:
            counts[p] += 1
            n //= p
    return counts, n


def phi_from_factors(counts) -> int:
    """Euler's totient from a full factorisation {prime: exponent}."""
    phi = 1
    for p, k in counts.items():
        phi *= p ** (k - 1) * (p - 1)
    return phi


q = gcd(n1, n2)                  # shared prime between n1 and n2
p, r = n1 // q, n2 // q

counts, rest = divide_out(n3, [p, q, r])
if rest > 1:
    assert isprime(rest), "leftover cofactor is not prime; factorisation incomplete"
    counts[rest] += 1            # the fourth prime, s

for f, k in counts.items():
    print(f"{f.bit_length()}-bit prime, exponent {k}")

phi = phi_from_factors(counts)
d = pow(e, -1, phi)
print(long_to_bytes(pow(c, d, n3)))
```

The output is the flag (`bi0s{...}`).

One more observation: the plaintext was only a few hundred bits long, smaller than any single 1024-bit factor. That means knowing *any one* prime `f` of the modulus was enough on its own. Decrypting modulo `f` with `d_f = e^-1 mod (f - 1)` already gives `m`. Leaking even a single factor of a multi-prime modulus breaks it.

### Defensive takeaway

- **Multi-prime RSA is legitimate, home-made variants are not.** The PKCS #1 standard ([RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)) allows more than two primes, but they must all be distinct, independently generated, and secret. Repeating a prime (`p^3`) adds bits to the modulus without adding any security, and publishing other moduli built from the same primes hands the factors to anyone who can run a GCD.
- **A bigger modulus is not a stronger key if its parts are reused.** `n3` was over 7000 bits, and it fell to the same one-line GCD as a toy example.
- **When a challenge or system says "RSA", check its parameters.** Bit lengths, how many primes, whether any moduli are related, and what `e` is: these are the first things I look at now, because each one points to a specific weakness.

## Takeaways

- **Every RSA attack here is a factoring shortcut.** Once `p` and `q` (or all prime factors) are known, `d = pow(e, -1, phi)` and decryption are mechanical. Breaking RSA almost always means finding out how the primes were chosen badly.
- **`gcd` is the first thing to try** whenever more than one modulus is in play. Shared primes have factored real-world keys, not just CTF ones.
- **Close primes fall to Fermat's method.** The work grows with the square of the gap between `p` and `q`, so primes derived from each other (`next_prime(p)`) are broken immediately.
- **Don't generate RSA parameters yourself.** Use a vetted library with a properly seeded CSPRNG, independent primes, enforced prime distance, unique moduli per key, and OAEP padding. Every bug in this post is a step a good library already does correctly.

*Tools: Python 3 (`math.gcd`, `math.isqrt`, three-argument `pow`), sympy for primality checks. Challenges: "Common Primes", "Common Thread", "Too close for comfort", and "Is it RSA", DD CTF by team bi0s.*
