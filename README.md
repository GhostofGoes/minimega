minimega
========

minimega is a tool for launching and managing virtual machines. It can run on
your laptop or distributed across a cluster. minimega is fast, easy to deploy,
and can scale to run on massive clusters with virtually no setup.

See [sandia.gov/minimega](https://www.sandia.gov/minimega/) for more info.

## Contributing

This repository uses [prek](https://prek.j178.dev/) (a Rust drop-in alternative
to `pre-commit`) to enforce repository-wide checks (shell linting, YAML
linting, Dockerfile linting, spell-checking, conventional commit messages, and
general hygiene). The same checks run in CI via the
[Lint workflow](.github/workflows/lint.yml).

Install the dev tooling and register the git pre-commit hooks once:

```bash
make install-dev
```

Run all hooks against every file manually:

```bash
make lint
# or, equivalently
prek run --all-files
```

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for additional contribution
guidelines, including conventional commit conventions and EditorConfig setup.
