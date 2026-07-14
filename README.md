# DecodeLabs Python Internship — Project 3: Random Password Generator

A terminal-based cryptographic password generator built as Week 3's milestone project for the DecodeLabs Python Programming Internship (Batch 2026). It generates high-entropy passwords using OS-level randomness, validates input against NIST 2024 standards, and displays a full security analysis with Shannon entropy metrics.

## Overview

The script follows a strict IPO (Input → Process → Output) architecture with each phase isolated into its own function. Password generation uses `secrets.choice()` — backed by the OS CSPRNG (`/dev/urandom` on Linux, `CryptGenRandom` on Windows) — rather than the deterministic `random` module, making it suitable for real credential generation.

## Features

- Cryptographically secure generation via `secrets.choice()` (not Mersenne Twister)
- O(N) string assembly using `''.join()` on a generator expression (avoids O(N²) `+=` pattern)
- Character pool from `string` module: `ascii_letters` + `digits` + `punctuation` (94 chars)
- NIST SP 800-63B (2024) compliant — enforces a minimum of 15 characters
- Rigorous input validation — rejects empty input, non-integers, floats, and out-of-range values
- Shannon entropy calculation: `E = L × log₂(R)` with colour-coded security classification
- Brute-force difficulty estimate (2^entropy combinations)
- Colored, cross-platform terminal UI (pure ANSI codes, UTF-8 safe on Windows)
- Graceful handling of `Ctrl+C` / `Ctrl+Z` / `Ctrl+D`
- IPO-decoupled architecture — input, processing, and output in separate functions

## Requirements

- Python 3.6 or later
- No external packages or `pip install` needed — built entirely with the Python standard library

## How to Run

```bash
python3 password_generator.py
```

Enter a password length (minimum 15) and press Enter. The tool will generate a secure password and display its entropy analysis.

## Example Session

```
+==============================================================+
|       [*]  CRYPTOGRAPHIC RANDOM PASSWORD GENERATOR       |
|            Enterprise Security Tool  .  v1.0.0            |
+==============================================================+
  Engine  : secrets.choice() -- OS-level CSPRNG (urandom)
  Pool    : 94 characters (A-Z, a-z, 0-9, symbols)
  Standard: NIST SP 800-63B (2024) compliant

  +--------------------------------------------------------------+
  |  INPUT  .  Password Configuration
  +--------------------------------------------------------------+

  Minimum length: 15 characters (NIST 2024 standard)
  Maximum length: 128 characters

  > Enter desired password length: abc
  [X] Error: 'abc' is not a valid integer. Please enter a whole number.

  > Enter desired password length: 10
  [X] Error: Length 10 is below the minimum of 15 characters.
    NIST SP 800-63B (2024) requires >=15 for adequate entropy.

  > Enter desired password length: 20

  +--------------------------------------------------------------+
  |  OUTPUT  .  Generated Password
  +--------------------------------------------------------------+

  +------------------------------------------------------------+
  |  Bfq.(OY!5k+Yim8d3Dcf
  +------------------------------------------------------------+

  +--------------------------------------------------------------+
  |  METRICS  .  Security Analysis
  +--------------------------------------------------------------+

  > Password Length      : 20 characters
  > Character Pool (R)   : 94 unique characters
    [a-z] [A-Z] [0-9] [!@#$%^&*...]
  > Entropy (E = L*log2R): 131.09 bits
  > Security Rating      : [EXCELLENT]
  > Brute-Force Space    : 2^131.09 = 2.90e+39 combinations

  ..............................................................
    Entropy Reference Scale:
    ####................  < 60 bits  -> Weak
    ########............  60-80 bits -> Fair
    ############........  80-100 bits -> Strong
    ####################  > 100 bits -> Excellent
  ..............................................................

+==============================================================+
|  [!] Store this password in a trusted password manager.      |
|  [!] Never reuse passwords across multiple services.         |
|  [!] Clipboard will NOT be modified -- copy manually.        |
+==============================================================+
```

## Project Structure

```
decodelabs-python-project3/
├── password_generator.py
└── README.md
```

## Concepts Demonstrated

- Input → Process → Output (IPO) model with strict function decoupling
- Cryptographic randomness (`secrets` module) vs. pseudo-randomness (`random` module)
- Shannon information entropy and brute-force key-space analysis
- Defensive coding with `try/except` for multiple error classes
- O(N) string construction via generator expressions and `''.join()`
- NIST SP 800-63B (2024) compliance for password length policy

## Author

Nalain Muhammad — DecodeLabs Python Programming Internship, Batch 2026