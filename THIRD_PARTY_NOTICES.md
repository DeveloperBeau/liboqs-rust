# Third-party notices

This project is a Rust port of liboqs. A port is a derived work, so the authors of the original code keep their credit and their license terms. Each algorithm family crate also carries the license and copyright of the code that it translates. This file lists every upstream project that the repository uses. A change that ports a new family adds its section here in the same change.

## liboqs

- Project: [Open Quantum Safe liboqs](https://github.com/open-quantum-safe/liboqs)
- Authors: the Open Quantum Safe project authors. See the liboqs `CONTRIBUTORS` file.
- Version: the version in `LIBOQS_VERSION`.
- Use in this repository: the source of truth for behavior, the test oracle, and the known-answer test data.
- License: MIT. liboqs also includes third-party code under other licenses. Each family section in this file names the license of that code.

```text
The MIT license, the text of which is below, applies to liboqs in general.
liboqs includes some third party libraries or modules that are licensed
differently; the corresponding subfolder contains the license that applies in
that case.


Copyright (c) 2016-2024 The Open Quantum Safe project authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BearSSL (AES)

- Project: [BearSSL](https://bearssl.org/), by Thomas Pornin, through liboqs `src/common/aes/aes_c.c`.
- Use in this repository: `Modules/AES` translates the constant-time bitsliced AES (`aes_ct64`) of that file.
- License: MIT.

```text
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## SHA-2 and SHA-3

`Modules/SHA2` and `Modules/SHA3` are written from FIPS 180-4 and FIPS 202. They are not translations of the liboqs code. They follow the incremental API of liboqs `src/common/sha2` and `src/common/sha3`, so the families call them in the same way as the C code calls liboqs.

## NIST known-answer generator

- Project: the NIST submission package, through liboqs `src/common/rand/rand_nist.c`.
- Use in this repository: `Modules/KATRandom` translates the AES-256 CTR DRBG of that file for the known-answer tests. The port keeps the state in a value, not in a global variable.
- Notice:

```text
NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
```

## ML-KEM and Kyber

- Algorithm: CRYSTALS-Kyber, by Peter Schwabe, with Roberto Avanzi, Joppe Bos, Léo Ducas, Eike Kiltz, Tancrède Lepoint, Vadim Lyubashevsky, John M. Schanck, Gregor Seiler and Damien Stehlé. ML-KEM is its standard form, NIST FIPS 203. See https://pq-crystals.org/kyber/ and https://csrc.nist.gov/pubs/fips/203.
- ML-KEM in liboqs: [mlkem-native](https://github.com/pq-code-package/mlkem-native) of the PQ Code Package, commit `0ba906cb14b1c241476134d7403a811b382ca498`. License: Apache-2.0 OR ISC OR MIT.
- Kyber in liboqs: the reference code of the Kyber team, [pq-crystals/kyber](https://github.com/pq-crystals/kyber), commit `441c0519a07e8b86c8d079954a6b10bd31d29efc` with the liboqs patches. License: CC0-1.0 OR Apache-2.0.
- Use in this repository: `Modules/MLKEM` follows FIPS 203 and the Kyber submission of round 3, and gives the bytes of these two implementations. The port is under MIT, and the `license` field of the crate states the combined expression `MIT AND (Apache-2.0 OR ISC OR MIT) AND (CC0-1.0 OR Apache-2.0)`.

## FrodoKEM

- Algorithm: FrodoKEM, by Michael Naehrig, Erdem Alkim, Joppe Bos, Léo Ducas, Karen Easterbrook, Brian LaMacchia, Patrick Longa, Ilya Mironov, Valeria Nikolaenko, Christopher Peikert, Ananth Raghunathan and Douglas Stebila. eFrodoKEM is its ephemeral form. See https://frodokem.org/.
- FrodoKEM in liboqs: the reference code of the FrodoKEM team, [PQCrypto-LWEKE](https://github.com/microsoft/PQCrypto-LWEKE) of Microsoft, commit `a2f9dec8917ccc3464b3378d46b140fa7353320d`, in `src/kem/frodokem`. License: MIT, the SPDX identifier that liboqs gives the upstream code in `docs/algorithms/kem/frodokem.yml` and in the headers of its FrodoKEM files.
- Use in this repository: `Modules/FrodoKEM` translates the portable C code of FrodoKEM and eFrodoKEM, and gives its bytes. The port is under MIT, the license of the upstream code, so the crate keeps the license of the workspace.

## HQC

- Algorithm: HQC, Hamming Quasi-Cyclic, by Philippe Gaborit, with Carlos Aguilar-Melchor, Nicolas Aragon, Slim Bettaieb, Loïc Bidoux, Olivier Blazy, Jean-Christophe Deneuville, Edoardo Persichetti, Gilles Zémor, Jurjen Bos, Arnaud Dion, Jérôme Lacan, Jean-Marc Robert, Pascal Véron, Paulo L. Barreto, Santosh Ghosh, Shay Gueron, Tim Güneysu, Rafael Misoczki, Jan Richter-Brokmann, Nicolas Sendrier, Jean-Pierre Tillich and Valentin Vasseur. NIST selected HQC for standardization. See https://pqc-hqc.org/.
- HQC in liboqs: the reference code of the HQC team, [pqc-hqc/hqc](https://gitlab.com/pqc-hqc/hqc), commit `161cd4fdf6b4a5198cf40b3a1243f9f27f13e03d` with the liboqs patches, for the specification of 2025-08-22.
- License: public domain. liboqs states it as `spdx-license-identifier: Public domain` in `docs/algorithms/kem/hqc.yml`. The folders `src/kem/hqc/pqc-hqc_*` have no license file and no license header. The liboqs wrappers `src/kem/hqc/kem_hqc.h` and `kem_hqc_1.c` to `kem_hqc_5.c` are MIT, as liboqs is.
- The C code cites Algorithm 5 of ePrint 2021/1631 for its fixed-weight sampler of encryption, and Shuhong Gao and Todd Mateer, with the radix conversion of Bernstein, Chou and Schwabe, for its additive FFT.
- Use in this repository: `Modules/HQC` translates the reference code and gives its bytes. The port is under MIT, which a public domain upstream allows.

## Test vectors

- [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server), tag `v1.1.0.41`: the ML-KEM vectors. Works of the United States government are not subject to copyright in the United States.
- [Wycheproof](https://github.com/C2SP/wycheproof) of C2SP, commit `032b56abd1368843e4def50b4975032ec1ec7ba4`: the ML-KEM vectors. License: Apache-2.0.
- The repository holds the addresses and SHA-256 of these files in `Documentation/Registers/TestVectors.md`, and not the files. `cargo xtask fetch-oracle` downloads them for the tests.
