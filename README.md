# dit

*dit* (*d*istributed g*it*) is a wrapper around `git` providing threshold signatures for (annotated) tags, using the one online round threshold signature protocol introduced by Gennaro and Goldfeder, 2020 [1](https://eprint.iacr.org/2020/540). These signatures are OpenPGP-compatible, and can be verified via `git tag -v <tag-name>`.

The idea behind `dit` was to introduce a tool that encourages code auditing and informal consensus over what gets included in releases, as part of an effort to provide more holistic security for package managers and associated workflows. Currently, a lot of packages get built and submitted to package repositories as part of some CI script on releases or version tags, and if the code does not get audited, malicious actors might inject commands 

For more details about the motivation behind the project and its design, please refer to [my thesis on the matter](link coming soon!).


When in a `git` repository, `dit` will check for a `config.toml` file at its root (sample below), and will use the specified channel for any pending operations before presenting the choice to participate to the user.

```toml
project = "sample"
participants = 4
threshold = 2


[server]
address = "localhost"
port = 8000
```

We have only implemented a single, HTTP channel, with a server to go with it, which can be thought of as a 'bootstrap' channel. When running for the first time, the key generation part of the protocol (the phase that can be computed without the message) is run to completion, meaning all of the participants get their share of the private key in the `.dit` folder. Furthermore, to ensure the legitimacy of the key, we collaboratively self-sign it to indicate that the participants indeed possess sufficient shares to recreate the private key.

## Dependencies
- GnuPG version 2.1, compiled with `libgcrypt >= 1.7.0`: this is the first version of GnuPG that added support for elliptic curves, including the `secp256k1` (Bitcoin) curve that we are using as part of the multi-party ECDSA library.
- `git` recent enough to support tags
- GNU Coreutils
- Rust version `1.56.0-nightly` (may work with, but has not been tested with other versions)

## Examples

Key generation with external commands working:
[![asciicast](https://asciinema.org/a/zT7t0ziL8r6Dh8bXQTe2R67kR.svg)](https://asciinema.org/a/zT7t0ziL8r6Dh8bXQTe2R67kR)

Producing and verifying tags:
[![asciicast](https://asciinema.org/a/19O9LazuZ3qJqeyBeUcn76Ax8.svg)](https://asciinema.org/a/19O9LazuZ3qJqeyBeUcn76Ax8)

## Usage
`dit` introduces two new commands:
 - `keygen` initiate the key generation protocol. Given a complete `config.toml` file, it does not take any arguments for maximum ease of use.
 - `start-tag`: initiate the distributed tagging. This is semantically as close as possible to the normal tagging process, with the user's `$EDITOR` being launched to indicate the tag message. Note that it takes an optional commit hash, with the `HEAD` being used by default

## Local Testing
1. Run the `server` executable in the background
3. Make four different copies of the repository you are going to be working on, to mimic the distributed workflow (running four instances of the threshold signing protocols in the same folder was not an intended use-case, and the executable outputs its intermediary files to the `.dit` directory under a hard-coded name).
4. Start the leader by running `dit keygen`.
5. Run the executable in the other copies of the directories with any `dit` command (`dit` will do, as will `dit` followed by any Git subcommand)
6. Each of the executables will present you with an option of participating in the key generation
7. (Optional) When the protocol is completed, you can check in the public key (created under the `.dit` directory as `.gpg` file) into Git
8. When you want to create a tag, run `dit start-tag [tag_name]` and enter a tag message.
9. Proceed as in step 5
10. When the protocol is done, you can verify the tag on the leader's repository by running `gpg --import .dit/pubkey.gpg` (replacing the name of the keyfile) and then `git tag -v [tag_name]`. Note that the key only has its own signature, which GPG interprets to mean that it is not trustworthy.

## Limitations

While sufficiently fully featured, `dit` lacks additional channels that would not require the user to always be online, and it is fairly inflexible in terms of the protocol. In theory, the GG20 protocol has two 'operating modes': the standard threshold signature mode, involving the distributed key generation and collaborative signing protocols; and the online-offline mode, where you conceptually move part of the signing operations to the time of key generation. The latter mode allows us to use a single online round to compute the signature, at the expense of pre-selecting the signers at the time of key generation.

Furthermore, the current version of the project is pinned to an older version of the [multi-party ECDSA library](https://github.com/ZenGo-X/multi-party-ecdsa) we started out with. Newer versions of the library added support for running the protocol portion asynchronously, as well as fixing several potential safety concerns.

Another point worth investigating is _how_ to present code changes to the user. When normally reviewing commits with `git show <commit>` or `git log -p`, it might be hard to figure out the exact changes, especially if they were purposefully designed to evade review. 

## Future work
- [ ] Handling changing developer groups: the group of developers working on a project does not remain constant over time, and implementing ways of redistributing key shares would help make the process more seamless
- [ ] Key rotation: to ensure that a determined attacker could not eventually obtain sufficient key shares to unilaterally sign releases, an efficient key rotation protocol (like the one found [here](https://github.com/ZenGo-X/fs-dkr)) could be implemented
- [ ] Secure communication (hashing broadcast messages according to the protocol description)
- [ ] Better error handling between the protocol execution and the front-end
- [ ] More semantically descriptive errors for protocol failure
- [ ] Channels: having an `enum` with all possible channel types might be the simplest way
- [ ] Async integration: all of the networking requests could be done asynchronously, and we already depend on an async runtime lower down in the dependency stack
- [ ] More user choice: currently, the directories where the keys are stored are hard-coded and might conflict with existing ones
- [ ] Keyid file: the GPG key ID is best generated when the key is parsed into an internal data representation, but we have focused our efforts purely on exporting GPG keys, not interpreting them for further data. Currently, we store the key ID of the current key in `.dit/keyid`, but this seems like a hack
- [ ] Reducing communication: currently, `dit` phones home after every invocation, which could be reduced if we could set some sort of timer between invocations (have it run as a server) or have an environment variable be decremented upon every invocation.
- [ ] Reduing GPG noise: without additional signatures to indicate the identity of the user, GPG will always say that the identity of the user has not been vouched for by any third party. If the key gets checked into version control (which is the simplest current path for distribution), then the participants can sign the public key and commit the change, though there might be other avenues to explore.
