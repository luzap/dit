# dit

*dit* (*d*istributed g*it*) is a wrapper around `git` providing threshold signatures for (annotated) tags, using the one online round threshold signature protocol introduced by Gennaro and Goldfeder, 2020 [1](https://eprint.iacr.org/2020/540). These signatures are OpenPGP-compatible, and can be verified via `git tag -v <tag-name>`.

When in a `git` repository, `dit` will check for a `config.toml` file at its root, and will only be usable when such a configuration file is available.

## Dependencies
- GnuPG version 2.1, compiled with `libgcrypt >= 1.7.0`
- `git` recent enough to support tags
- GNU Coreutils

## Usage
`dit` introduces two new commands:
 - `keygen` initiate the key generation protocol using an extern
 - `start-tag`: 


## Work in progress
- [ ] Blame
- [ ] Better error reporting
- [ ] New communication channels for signing
- [ ] Secure communication infrastructure (signing the hash of all previous messages)
