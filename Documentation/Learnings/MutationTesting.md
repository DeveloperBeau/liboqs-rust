# Mutation testing

## Index arithmetic that only skips ahead gives equivalent mutants

- **Trap.** A scanner that moves an index past a bracket with `position = close + 1` gives the same result with `position = close`, because the next loop step skips the bracket anyway. A mutant of that line survives, and no test can kill it.
- **Finding.** The first mutation run of `Tools/Xtask` had 106 surviving mutants in the declaration scanner. Most were of this kind.
- **Rule.** Group the tokens by brackets first (`TokenTree`). Then a handler steps over a group as one item, and a step that is wrong by one changes the result. Leave a group that the main loop can enter without harm for the main loop, and step over only the groups that must not be entered.

## Equivalent at one level is not equivalent at the level below

- **Trap.** A tokenizer mutant can give the same declaration list for every test source, although the token list is different.
- **Finding.** Mutants in the character literal code survived the scanner tests. A tokenizer test that compares the whole token list kills them.
- **Rule.** Test each layer at its own output. Test the tokenizer with token lists, the tree builder with tree shapes, and the scanner with declarations.

## A loop without progress hangs instead of failing

- **Trap.** A mutant that stops a loop from moving makes the suite hang. The run waits for its timeout, which is slow, and the result says "timeout", not the name of a test.
- **Finding.** The first run had 111 timeouts at 20 seconds each, which was most of its 14 minutes.
- **Rule.** Put a `debug_assert!` of progress in each main loop, so a stuck loop fails at once with a message. Keep a short test timeout in `.cargo/mutants.toml`. A timeout still counts as caught.

## The mutation copy of the tree has no git folder

- **Trap.** `cargo mutants` copies the source tree without `.git`, so a test that runs git on the repository itself fails in the copy and stops the run.
- **Finding.** The contract test of `DiskFileSystem` must run git, because the adapter calls git.
- **Rule.** A test that needs git makes its own repository in a temporary folder and deletes it at the end. No test reads the git state of the repository that it tests.
