# Repository Rules

1. Use CRLF except in lock files. Manually inspect line endings after each change; do not enforce them through configuration or CI. Keep lock files in their tool-generated format.
2. Remove dead code, including code unreachable from the CLI. Unused constants in `const.py` are exempt.
3. No unit or integration test code. Preserve the existing CLI `test` command and CI PCK regression checks.
4. Before each developer build, refresh relevant lock files to the latest compatible dependency versions and explain blocked updates. CI need not refresh locks. Offline or `--locked` builds alone do not count as a refresh.
5. Ask before creating files unless the user already explicitly requested their creation. Editing existing files needs no separate approval.
6. Prefer mainstream packages and minimize the total package count, including transitive dependencies.
7. Align directly user-observable behavior across Windows, Linux, macOS, and other supported platforms. Internal behavior and CLI wording (including prompts and errors) may differ.
8. Keep corresponding Rust and Python implementations behaviorally aligned.
9. Keep both language versions of the manuals aligned with the implementation and with each other.
10. For every diff, manually run and pass all lint checks defined in CI.
11. Code comments are prohibited.
12. Do not document scripts/ or CI in either manual or the changelog; they are outside the project's scope.
13. Do not modify changelog entries for released versions.
14. Avoid pure forwarding functions with only a few references.
15. Unsafe Rust is prohibited.
