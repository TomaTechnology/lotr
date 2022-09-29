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

cargo run setup
# Setup configurations for network host, bitcoin host and mute list

cargo run key
# Displays all the master key subcommands

cargo run key generate 
# Creates a new master key and encrypts it 

cargo run key import 
# Imports a master key from a mnemonic and encrypts it

cargo run key status
# Shows existing keys in storage

cargo run key delete
# Deletes the selected key

cargo run network invite
# ADMIN COMMAND to invite new users by generating an invite code

cargo run network join
# Join the network using an invite code from an admin

cargo run network members
# View all members on the network

cargo run network sync
# Blocks the terminal with a strem of messages from the network

cargo run network post
# Posts a message to another member

cargo run contract new
# Starts a new contract

cargo run contract info
# Gets status of a contract and displays history and balance of an active contract

cargo run contract receive
# Gets an address to receive bitcoin into the contract

cargo run contract send
# Makes a payment from the contract
```

### Releases

### Build from source

Build and copy binary to a bin directory

```bash
cargo build --release
cp target/release/lotr /usr/local/bin
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