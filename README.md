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

## Local Testing
1. Make a `.dit` folder at the root of Git repository (`mkdir $(git rev-parse --show-toplevel)/.dit` will do the job). 
2. Then, run the `server` executable in the background
3. Make four different copies of the repository you are going to be working on, to mimic the distributed workflow (running four instances of the threshold signing protocols in the same folder was not an intended use-case, and the executable outputs its intermediary files to the `.dit` directory under a hard-coded name). 
4. Start the leader by running `dit keygen`. 
5. Run the executable in the other copies of the directories with any `dit` command (`dit` will do, as will `dit` followed by any Git subcommand)
6. Each of the executables will present you with an option of participanting in the key generation
7. (Optional) When the protocol is completed, you can check in the public key (created under the `.dit` directory as `.gpg` file) into Git
8. When you want to create a tag, run `dit start-tag [tag_name]` and enter a tag message.
9. Proceed as in step 5
10. When the protocol is done, you can verify the tag on the leader's repository by running `gpg --import .dit/pubkey.gpg` (replacing the name of the keyfile) and then `git tag -v [tag_name]`. Note that this output verifies that the signature is good, but does not include the CRC that is part of the ASCII-armoring (for the sake of simplicity), and that the key only has its own signature, which GPG interprets to mean that it is not trustworthy.


## Limitations

While sufficiently fully featured to at least experiment with, `dit` lacks additional channels that would not require the user to always be online.

## Future work
- [ ] Secure communication (hashing broadcast messages)
- [ ] Better ergonomics
- [ ] More user-readable errors
