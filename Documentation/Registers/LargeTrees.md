# Large trees

The parity results of the stateful sets with a tree of height 20 or more, which `parity run` skips without `--large-trees`. Each run checks the base case and 1000 variations, or the signatures that the key holds, against the C library with the seed of the gate. A row takes its result from the run that it names.

The 19 sets of height 20 run in the `Large trees` workflow, one job per set. The four LMS sets of height 25 take longer than the six hours of a hosted job, so they run with `parity run --cases 1000 --large-trees --only <set>` on a machine of their own, with the build of the commit that the row names.

| Set | Where | Result | Run |
|---|---|---|---|
| `LMS_SHA256_H20_W1` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W2` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W4` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W8` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W8_H10_W8` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W8_H15_W8` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W8_H20_W8` | `Large trees` workflow | running |  |
| `LMS_SHA256_H20_W8_H5_W8` | `Large trees` workflow | running |  |
| `XMSS-SHA2_20_192` | `Large trees` workflow | running |  |
| `XMSS-SHA2_20_256` | `Large trees` workflow | running |  |
| `XMSS-SHA2_20_512` | `Large trees` workflow | running |  |
| `XMSS-SHAKE256_20_192` | `Large trees` workflow | running |  |
| `XMSS-SHAKE256_20_256` | `Large trees` workflow | running |  |
| `XMSS-SHAKE_20_256` | `Large trees` workflow | running |  |
| `XMSS-SHAKE_20_512` | `Large trees` workflow | running |  |
| `XMSSMT-SHA2_40/2_256` | `Large trees` workflow | running |  |
| `XMSSMT-SHA2_60/3_256` | `Large trees` workflow | running |  |
| `XMSSMT-SHAKE_40/2_256` | `Large trees` workflow | running |  |
| `XMSSMT-SHAKE_60/3_256` | `Large trees` workflow | running |  |
| `LMS_SHA256_H25_W1` | `parity run` on a machine of its own | running |  |
| `LMS_SHA256_H25_W2` | `parity run` on a machine of its own | running |  |
| `LMS_SHA256_H25_W4` | `parity run` on a machine of its own | running |  |
| `LMS_SHA256_H25_W8` | `parity run` on a machine of its own | running |  |
