# Large trees

The parity results of the stateful sets with a tree of height 20 or more, which `parity run` skips without `--large-trees`. Each run checks the base case and 1000 variations, or the signatures that the key holds, against the C library with the seed of the gate. A row of the `Large trees` workflow takes its result from the run that it names, on the commit `99c8748`. A row of a local run ran on the commit `63fb0c0` of `develop`. The code of the port and of the parity program is the same on both commits.

The 19 sets of height 20 run in the `Large trees` workflow, one job per set, on a push to a branch under `large-trees/`. The four LMS sets of height 25 take longer than the six hours of a hosted job, so they run on a local machine, one process per set, with `parity run --cases 1000 --large-trees --only <set>`. A push to a branch under `large-trees-25/` runs them on a self-hosted runner with the label `large-trees` instead.

| Set | Where | Result | Run |
|---|---|---|---|
| `LMS_SHA256_H20_W1` | `Large trees` workflow | base case and 1000 variations identical, 14 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W2` | `Large trees` workflow | base case and 1000 variations identical, 13 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W4` | `Large trees` workflow | base case and 1000 variations identical, 23 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W8` | `Large trees` workflow | base case and 1000 variations identical, 181 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W8_H10_W8` | `Large trees` workflow | base case and 1000 variations identical, 115 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W8_H15_W8` | `Large trees` workflow | base case and 1000 variations identical, 141 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W8_H20_W8` | `Large trees` workflow | base case and 1000 variations identical, 145 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H20_W8_H5_W8` | `Large trees` workflow | base case and 1000 variations identical, 145 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHA2_20_192` | `Large trees` workflow | base case and 1000 variations identical, 45 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHA2_20_256` | `Large trees` workflow | base case and 1000 variations identical, 58 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHA2_20_512` | `Large trees` workflow | base case and 1000 variations identical, 95 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHAKE256_20_192` | `Large trees` workflow | base case and 1000 variations identical, 42 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHAKE256_20_256` | `Large trees` workflow | base case and 1000 variations identical, 58 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHAKE_20_256` | `Large trees` workflow | base case and 1000 variations identical, 51 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSS-SHAKE_20_512` | `Large trees` workflow | base case and 1000 variations identical, 147 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSSMT-SHA2_40/2_256` | `Large trees` workflow | base case and 1000 variations identical, 116 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSSMT-SHA2_60/3_256` | `Large trees` workflow | base case and 1000 variations identical, 171 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSSMT-SHAKE_40/2_256` | `Large trees` workflow | base case and 1000 variations identical, 116 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `XMSSMT-SHAKE_60/3_256` | `Large trees` workflow | base case and 1000 variations identical, 174 minutes | [run 40157881401](https://github.com/DeveloperBeau/liboqs-rust/actions/runs/40157881401) |
| `LMS_SHA256_H25_W1` | local run, macOS on Apple silicon | base case and 1000 variations identical, 382 minutes | local |
| `LMS_SHA256_H25_W2` | local run, macOS on Apple silicon | base case and 1000 variations identical, 357 minutes | local |
| `LMS_SHA256_H25_W4` | local run, macOS on Apple silicon | base case and 1000 variations identical, 581 minutes | local |
| `LMS_SHA256_H25_W8` | local run, macOS on Apple silicon | running | local |

The four sets of height 25 ran at once, one process per set, on a Mac with Apple silicon. A set of height 25 takes about 26 times as long there as its set of height 20 in the workflow, so `LMS_SHA256_H25_W8` needs about 3 days of processor time. Its machine slept for part of the run, so the wall time of the run is longer. The C library of that run builds the ARM code of some other families, such as ML-DSA and Falcon. LMS has no ARM code, so both sides of these four sets run the same portable code as in the workflow.
