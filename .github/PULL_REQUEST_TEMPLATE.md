Please fill in the following form before submitting this PR:

- Affected components
    - [ ] README and global configurations
    - [ ] Linux PAL
    - [ ] SGX PAL
    - [ ] FreeBSD PAL
    - [ ] Library OS (i.e., SHIM), including GLIBC

- A brief description of this PR (describe the reasons and measures)




- How to test this PR?
    - [ ] Documentation-only; no need to test




Please follow the [coding style guidelines](CODESTYLE.md). Do not submit PRs which violate these rules.
- [ ] Comments and commit messages: no spelling or grammatical errors
- [ ] 4 spaces per indentation level, at most 100 chars per line
- [ ] Asterisks (`*`) next to types: `int* pointer;` (one pointer each line)
- [ ] Braces (`{`) begin in the same line as function names, `if`, `else`, `while`, `do`, `for`, `switch`, `union`, and `struct` keywords.
- [ ] Naming: Macros, constants - `NAMED_THIS_WAY`; global variables - `g_named_this_way`; others - `named_this_way`.
- Other styling issues may be pointed out by reviewers.


Please preserve the following checklist for reviewing:

- [ ] Pass all CI unit tests
- [ ] Resolve all discussions/requests from reviewers
- Reviewer approval (select one):
    - [ ] 3 approving reviews
    - [ ] 2 approving reviews and 5 days since the PR was created
    - [ ] The PR is from a maintainer; 1 approving review and 10 days since the PR was created
