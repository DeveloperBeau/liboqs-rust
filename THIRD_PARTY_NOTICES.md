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

## BIKE

- Algorithm: BIKE, Bit Flipping Key Encapsulation, by Nicolas Aragon, Paulo Barreto, Slim Bettaieb, Loïc Bidoux, Olivier Blazy, Jean-Christophe Deneuville, Philippe Gaborit, Santosh Ghosh, Shay Gueron, Tim Güneysu, Carlos Aguilar Melchor, Rafael Misoczki, Edoardo Persichetti, Nicolas Sendrier, Jean-Pierre Tillich, Valentin Vasseur and Gilles Zémor. See https://bikesuite.org.
- BIKE in liboqs: the additional implementation of round 4 by Nir Drucker, Shay Gueron and Dusan Kostic of the AWS Cryptographic Algorithms Group, from [awslabs/bike-kem](https://github.com/awslabs/bike-kem), in `src/kem/bike/additional_r4`. liboqs names the branch `master` and no commit.
- Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. License: Apache-2.0, in the `LICENSE` file of that folder and in the `SPDX-License-Identifier` line of each file. The liboqs wrapper `src/kem/bike/kem_bike.c` is MIT.
- Use in this repository: `Modules/BIKE` translates the portable files of that folder into Rust. The port is a modified work: it takes its random bytes as an argument, and it computes the carry-less products by another method that gives the same bytes. The crate is under MIT AND Apache-2.0.

## NTRU

- Algorithm: NTRU, by John M. Schanck, with Cong Chen, Oussama Danba, Jeffrey Hoffstein, Andreas Hülsing, Joost Rijneveld, Tsunekazu Saito, Peter Schwabe, William Whyte, Keita Xagawa, Takashi Yamakawa and Zhenfei Zhang. See https://ntru.org/.
- NTRU in liboqs: the clean code of [PQClean](https://github.com/PQClean/PQClean), commit `4c9e5a3aa715cc8d1d0e377e4e6e682ebd7602d6`, in `src/kem/ntru/pqclean_ntru*_clean`. PQClean took it from the reference code of the NTRU team, [jschanck/ntru](https://github.com/jschanck/ntru), commit `a43a4457`. The version text of liboqs names commit `6d96ed37` of the same repository.
- License: public domain, as the `LICENSE` file of each PQClean folder states. liboqs gives `spdx-license-identifier: CC0-1.0` in `docs/algorithms/kem/ntru.yml`. Some files name their SUPERCOP origin: `crypto_sort_int32.c` is based on `crypto_sort/int32/x86` of supercop-20190110, and `poly_r2_inv.c` and `poly_s3_inv.c` on `crypto_core/invhrss701` of supercop-20200702. The liboqs wrappers `src/kem/ntru/kem_ntru.h` and `kem_ntru_hps2048509.c` to `kem_ntru_hrss1373.c` are MIT, as liboqs is.
- Use in this repository: `Modules/NTRU` translates the clean code and gives its bytes. The sort of `crypto_sort_int32.c` is in `Modules/SortingNetwork`. The port is under MIT, which a public domain upstream allows, so the crate keeps the license of the workspace.

## NTRU Prime

- Algorithm: NTRU Prime, by Daniel J. Bernstein, Billy Bob Brumley, Ming-Shing Chen, Chitchanok Chuengsatiansup, Tanja Lange, Adrian Marotzke, Bo-Yuan Peng, Nicola Tuveri, Christine van Vredendaal and Bo-Yin Yang. sntrup761 is its Streamlined form. See https://ntruprime.cr.yp.to.
- sntrup761 in liboqs: `sntrup761.c` of [OpenSSH](https://github.com/openssh/openssh-portable), revision 1.9 of 2026-01-20, commit `1cc936b2fabffeac7fff14ca1070d7d7a317ab7b`, in `src/kem/ntruprime/sntrup761_openssh`. The file takes its code from SUPERCOP 20240808, and names Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange and Christine van Vredendaal as its authors.
- License: public domain, as the header of `sntrup761.c` and the `LICENSE` file of the folder state. liboqs gives `spdx-license-identifier: Public domain` in `docs/algorithms/kem/ntruprime.yml`. The liboqs wrappers `src/kem/ntruprime/kem_ntruprime.h` and `kem_ntruprime_sntrup761.c` are MIT, as liboqs is.
- Use in this repository: `Modules/NTRUPrime` translates `sntrup761.c` and gives its bytes. The sort of the file is in `Modules/SortingNetwork`. The port is under MIT, which a public domain upstream allows, so the crate keeps the license of the workspace.

## Sorting network (djbsort)

- Algorithm: djbsort, the constant-time sorting software of Daniel J. Bernstein in SUPERCOP. See https://sorting.cr.yp.to/.
- djbsort in liboqs: two copies. `crypto_sort_int32.c` of the four NTRU-HPS folders of PQClean, `src/kem/ntru/pqclean_ntruhps*_clean`, states that it is based on `crypto_sort/int32/x86` of supercop-20190110. `src/kem/ntruprime/sntrup761_openssh/sntrup761.c` holds `crypto_sort_int32` from `crypto_sort/int32/portable4/sort.c` of supercop-20240808, and `crypto_sort_uint32` on top of it.
- License: public domain, as liboqs ships both copies. The `LICENSE` file of each PQClean folder states public domain, and liboqs gives `spdx-license-identifier: CC0-1.0` for that code in `docs/algorithms/kem/ntru.yml`. The header of `sntrup761.c` and the `LICENSE` file of its folder state public domain, and liboqs gives `spdx-license-identifier: Public domain` in `docs/algorithms/kem/ntruprime.yml`.
- Use in this repository: `Modules/SortingNetwork` translates the sort for NTRU and NTRU Prime. The port is under MIT, which a public domain upstream allows, so the crate keeps the license of the workspace.

## ML-DSA

- Algorithm: CRYSTALS-Dilithium, by Vadim Lyubashevsky, with Shi Bai, Léo Ducas, Eike Kiltz, Tancrède Lepoint, Peter Schwabe, Gregor Seiler and Damien Stehlé. ML-DSA is its standard form, NIST FIPS 204. See https://pq-crystals.org/dilithium/ and https://csrc.nist.gov/pubs/fips/204/final.
- ML-DSA in liboqs: [mldsa-native](https://github.com/pq-code-package/mldsa-native) of the PQ Code Package, commit `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`. Copyright the mldsa-native project authors. Some files, such as `poly.c` and `ct.c`, also name the mlkem-native project authors. License: Apache-2.0 OR ISC OR MIT.
- Use in this repository: `Modules/MLDSA` follows FIPS 204 and the arithmetic of mldsa-native, and gives the bytes of that code. The port is under MIT, and the `license` field of the crate states the combined expression `MIT AND (Apache-2.0 OR ISC OR MIT)`.

## Falcon

- Algorithm: Falcon, by Pierre-Alain Fouque, Jeffrey Hoffstein, Paul Kirchner, Vadim Lyubashevsky, Thomas Pornin, Thomas Prest, Thomas Ricosset, Gregor Seiler, William Whyte and Zhenfei Zhang. See https://falcon-sign.info.
- Falcon in liboqs: the clean code of [PQClean](https://github.com/PQClean/PQClean), commit `1eacfdafc15ddc5d5759d0b85b4cef26627df181`, written by Thomas Pornin. License: MIT.
- Use in this repository: `Modules/Falcon` translates that code and gives its bytes. The port is under MIT, the license of the upstream code.

```text
This code is provided under the MIT license:

Copyright (c) 2017-2019  Falcon Project

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
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

It was written by Thomas Pornin <thomas.pornin@nccgroup.com>.

It has been reported that patent US7308097B2 may be applicable to parts
of Falcon. William Whyte, one of the designers of Falcon and also
representative of OnBoard Security (current owner of the said patent),
has pledged, as part of the IP statements submitted to the NIST for the
PQC project, that in the event of Falcon being selected for
standardization, a worldwide non-exclusive license to the patent will be
granted for the purpose of implementing the standard "without
compensation and under reasonable terms and conditions that are
demonstrably free of any unfair discrimination".
```

## MAYO

- Algorithm: MAYO, by Ward Beullens, with Fabio Campos, Sofía Celi, Basil Hess and Matthias J. Kannwischer, the principal submitters that liboqs names in `docs/algorithms/sig/mayo.yml`. MAYO is a candidate of round 2 of the NIST call for additional signatures. See https://pqmayo.org.
- MAYO in liboqs: the portable implementation of the MAYO team, [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C), commit `64e15c622dec1f59aa5bbaf7f7c8f4f20af75106` with the liboqs patches, in the folders `src/sig/mayo/pqmayo_mayo-<n>_opt`.
- Copyright 2023-2025 the MAYO team. All rights reserved. License: Apache-2.0, in the `LICENSE` and `NOTICE` files of each folder and in the `SPDX-License-Identifier` line of each file. The liboqs wrappers `src/sig/mayo/sig_mayo.h` and `sig_mayo_1.c` to `sig_mayo_5.c` are MIT.
- Use in this repository: `Modules/MAYO` translates the portable code into Rust and gives its bytes. The port is a modified work: it takes its random bytes as an argument, and it keeps its large arrays on the heap. The crate is under MIT AND Apache-2.0.

```text
Copyright 2023-2025 the MAYO team. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## SLH-DSA

- Algorithm: SPHINCS+, by Andreas Hülsing, with Daniel J. Bernstein, Christoph Dobraunig, Maria Eichlseder, Scott Fluhrer, Stefan-Lukas Gazdag, Panos Kampanakis, Stefan Kölbl, Tanja Lange, Martin M. Lauridsen, Florian Mendel, Ruben Niederhagen, Christian Rechberger, Joost Rijneveld, Peter Schwabe, Jean-Philippe Aumasson, Bas Westerbaan and Ward Beullens. SLH-DSA is its standard form, NIST FIPS 205. See https://sphincs.org/ and https://csrc.nist.gov/pubs/fips/205/final.
- SLH-DSA in liboqs: [slhdsa-c](https://github.com/pq-code-package/slhdsa-c) of the PQ Code Package, commit `a0fc1ff253930060d0246aebca06c2538eb92b88`, with the liboqs patch `internal_api.patch`. Copyright the slhdsa-c project authors, and for `slh_sys.h` also the mlkem-native project authors. License: Apache-2.0 OR ISC OR MIT, as the SPDX header of each file says. The wrappers and templates of each scheme are liboqs code under MIT.
- Use in this repository: `Modules/SLHDSA` follows FIPS 205 and the structure of slhdsa-c, and gives the bytes of that code. `Modules/SHA2` and `Modules/SHA3` give SHA-224, SHA-512/224, SHA-512/256 and SHA3-224 for its pre-hash forms, written from FIPS 180-4 and FIPS 202. The port is under MIT, and the `license` field of the crate states the combined expression `MIT AND (Apache-2.0 OR ISC OR MIT)`.

## CROSS

- Algorithm: CROSS, the Codes and Restricted Objects Signature Scheme, by Marco Baldi, Alessandro Barenghi, Michele Battagliola, Sebastian Bitzer, Patrick Karl, Felice Manganiello, Alessio Pavoni, Gerardo Pelosi, Federico Pintore, Paolo Santini, Jonas Schupp, Edoardo Signorini, Freeman Slaughter, Antonia Wachter-Zeh and Violetta Weger, with Marco Gianvecchio. See https://www.cross-crypto.com/.
- CROSS in liboqs: the clean code of [CROSS-lib-oqs](https://github.com/CROSS-signature/CROSS-lib-oqs) of the CROSS team, commit `179d61b8b59e524fba86954f7fa269495650030a`, version 2.2 with the PQClean and OQS patches, in `src/sig/cross`. The reference code is by Alessandro Barenghi, Marco Gianvecchio, Patrick Karl, Gerardo Pelosi and Jonas Schupp.
- License: CC0-1.0. Each folder `src/sig/cross/upcross_cross-*` holds the text of CC0 1.0 Universal in its `LICENSE` file, the header of each file states that the code is placed in the public domain, and liboqs states `spdx-license-identifier: CC0-1.0` in `docs/algorithms/sig/cross.yml`. The liboqs wrappers `src/sig/cross/sig_cross.h` and `sig_cross_*.c` are MIT, as liboqs is.
- Use in this repository: `Modules/CROSS` translates the clean code and gives its bytes. The port is under MIT, and the `license` field of the crate states the combined expression `MIT AND CC0-1.0`.

## UOV

- Algorithm: UOV, Unbalanced Oil and Vinegar, by Ward Beullens, Ming-Shing Chen, Jintai Ding, Boru Gong, Matthias J. Kannwischer, Jacques Patarin, Bo-Yuan Peng, Dieter Schmidt, Cheng-Jhih Shih, Chengdong Tao and Bo-Yin Yang, the principal submitters that liboqs names in `docs/algorithms/sig/uov.yml`. See https://www.uovsig.org/.
- UOV in liboqs: the reference code of the pqov project, [pqov/pqov](https://github.com/pqov/pqov), commit `33fa5278754a32064c55901c3a17d48b06cc2351`, in the folders `src/sig/uov/pqov_ov_<set>_ref`.
- License: the folders have no license file, and their files have no copyright line. Each file has the line `SPDX-License-Identifier: CC0 OR Apache-2.0`, and liboqs states the same in `docs/algorithms/sig/uov.yml`. CC0 has one version, CC0 1.0 Universal, so the SPDX expression is `CC0-1.0 OR Apache-2.0`. The liboqs wrappers `src/sig/uov/sig_uov.h` and `sig_uov_ov_<set>.c` and the build file `src/sig/uov/CMakeLists.txt` are MIT, as liboqs is.
- Use in this repository: `Modules/UOV` translates the reference code and gives its bytes. The port is a modified work: it takes its random bytes as an argument, it shares one code for the twelve sets, and it computes the products of the matrices in another order that gives the same bytes. The port is under MIT, and the `license` field of the crate states the combined expression `MIT AND (CC0-1.0 OR Apache-2.0)`.

## Test vectors

- [NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server), tag `v1.1.0.41`: the ML-KEM, ML-DSA and SLH-DSA vectors. Works of the United States government are not subject to copyright in the United States.
- [Wycheproof](https://github.com/C2SP/wycheproof) of C2SP, commit `032b56abd1368843e4def50b4975032ec1ec7ba4`: the ML-KEM and ML-DSA vectors. License: Apache-2.0.
- The repository holds the addresses and SHA-256 of these files in `Documentation/Registers/TestVectors.md`, and not the files. `cargo xtask fetch-oracle` downloads them for the tests.
