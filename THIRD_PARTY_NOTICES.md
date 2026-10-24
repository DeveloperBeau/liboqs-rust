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
