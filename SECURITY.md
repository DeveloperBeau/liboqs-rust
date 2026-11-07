# Security policy

## Supported versions

The latest release receives security fixes. The version of each crate equals the version of liboqs that it ports, so a fix to the port that keeps the liboqs version is a patch release of that version.

## Reporting a vulnerability

Report a vulnerability privately through the security advisories of this repository: the **Security** tab, then **Report a vulnerability**. Do not open a public issue for it. A report helps most with the algorithm name, the inputs that show the problem, and the output of the C library for the same inputs where that applies.

A difference from the output of liboqs 0.16.0 for the same random bytes is a defect of the port, and a report of one is welcome even when its security impact is unclear.

## Scope

- **In scope:** the shipped crates, for a difference from the C library, a panic or an endless loop on input that the C library handles, a secret that the API returns and does not wipe, and the use of `unsafe` code.
- **Out of scope:** weaknesses of an algorithm itself, which belong to its designers and to liboqs, and the behavior of the C library, which this port copies on purpose. `Documentation/KnownIssues.md` lists the places where the port follows the C library on hostile input.

## What the port does and does not do

- Each operation takes its random source as an argument. The security of a key depends on that source: use `SystemRandom` or another cryptographic source.
- `SecretBytes` wipes the secret keys and shared secrets that the API returns when they are dropped. The buffers inside an operation are not wiped.
- The port follows the constant-time structure of each C implementation that it translates. Its timing has not been measured.
- The stateful schemes XMSS, XMSS^MT and LMS need the advanced secret key of each signature to be stored before the signature is used. Reusing an old secret key reuses a one-time key and breaks the scheme.
