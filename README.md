# dit

*dit* (*d*istributed g*it*) is a wrapper around `git` providing threshold signatures for (annotated) tags, using the one online round threshold signature protocol introduced by Gennaro and Goldfeder, 2020 [1](https://eprint.iacr.org/2020/540). These signatures are OpenPGP-compatible, and can be verified via `git tag -v <tag-name>`.

When in a `git` repository, `dit` will check for a `config.toml` file at its root (sample below), and will use the specified channel for any pending operations before presenting the choice to participate to the user.

```toml
project = "sample"

[server]
address = "localhost"
port = 8000
```

We have only implemented a single, HTTP channel, with a server to go with it, which can be thought of as a 'bootstrap' channel. When running for the first time, the offline phase of the protocol (the phase that can be computed without the message)


## Dependencies
- GnuPG version 2.1, compiled with `libgcrypt >= 1.7.0`
- `git` recent enough to support tags
- GNU Coreutils
- Rust version `1.56.0-nightly` (may work with, but has not been tested)


## Usage
`dit` introduces two new commands:
 - `keygen` initiate the key generation protocol
 - `start-tag`: initiate the distributed tagging

## Limitations

While sufficiently fully featured to at least experiment with, `dit` lacks additional channels that would not require the user to always be online.

## Future work
- [ ] Secure communication (hashing broadcast messages)
- [ ] Better ergonomics
- [ ] More user-readable errors
