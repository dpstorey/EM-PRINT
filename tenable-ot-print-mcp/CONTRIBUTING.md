# Contributing

Thanks for your interest in this project. A few notes that will save us
both time.

## Before opening an issue or pull request

- **Search existing issues first.** Same bug, same idea, same question.
- **Be specific.** Version (image tag), Tenable OT/EM version, exact
  tool call, exact error. "Doesn't work" alone is hard to act on.

## Bug reports

Include a reproducible test case where you can — those get fixed
fastest.

## Feature requests

Open an issue describing the use case before writing code. This
project intentionally has a narrow scope (generating print-style
reports from Tenable One OT Exposure data); features outside that
scope will likely be declined.

## Pull requests

- Open an issue first if the change is non-trivial — saves you from
  writing code that won't get merged.
- One change per PR. Easier to review, easier to revert.
- Add tests for new behavior (`pytest`, under `tests/`). There's no CI
  pipeline running them automatically yet, so please run them
  yourself before opening the PR.
- Update `README.md` and `docs/tenable-ot-print-mcp-user-guide.md` if
  you add or change a tool, module, or parameter.
- Follow the existing code style — `ruff format` for Python, no
  configuration overrides.

## Coding standards

- Python 3.12+, async-first.
- Type hints on all public functions and tool implementations.
- No silent failures. Tools should raise informative errors that the
  consuming AI can surface to the user.
- A report module returns joined data and a rendered file path — it
  does not fabricate analysis or narrative content itself. (Same rule
  as the sibling `tenable-ot-mcp`/EM-MCP project.)

## Releases & versioning

This project follows [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking changes (tool/module removals, output-schema breaks).
- `MINOR` — new tools, new report modules, additive changes.
- `PATCH` — bug fixes only.

Releases are tagged in git; see `CHANGELOG.md` for what shipped in each.

## License

By contributing, you agree your contributions are licensed under
Apache 2.0 (the project's license).
