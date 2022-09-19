# Leverate of The Remnants

## a cli tool to facilitate multi-party bitcoin contracts


### Installation

First install rust's toolkit

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reference: https://www.rust-lang.org/tools/install
```

### Test

Run the unit tests:

NOTE: cypherpost unit tests will fail without a local instance of cypherpost server running.

For this reason these tests are ignored by default.

```bash
cargo test 
```

### Try the cli tool in debug mode

```bash

cargo run 
# Displays the command line options

cargo run mk
# Displays all the master key subcommands

cargo run mk generate --username "ishi"
# Creates a new master key and encrypts it 

cargo run mk import --username "bugs"
# Imports a master key from a mnemonic and encrypts it

cargo run mk status
# Shows existing keys in storage

cargo run mk delete --username "ishi"
# Deletes the selected key

```

### Releases

### Build from source

Build and copy binary to a bin directory

```bash
cargo build --release
chmod +x target/release/lotr
sudo cp target/release/lotr /usr/local/bin
```

#### Verifying a github release from toma.tech

All releases have a checksum provided by @i5hi after creating the builds.

Check each respective release for their respective checksum.

MAC
```bash
md5 /path/to/lotr
```

LINUX
```bash
md5sum /path/to/lotr
```

Download it.

Copy binary to a bin directory

RUN IT!

```bash
lotr
```

### Local Storage

SledDb creates its database at `~/.lotr`

If you want to purge all your local data, just delete this folder.

After you back up your seed words and your contract, you can safely purge local data without losing access to your funds or social account.