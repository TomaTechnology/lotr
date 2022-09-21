# Models

cypherpost as a server seeks to do the most minimal work possible to facilitate private e2ee message forwarding for its clients.

The server side data model is minimal and the client's are tasked with Data Modeling and Management.

## Server model

`cypher` with some additional metadata is stored on the server as follows:

```rust
ServerPostModel{
    id: String,
    genesis: u64,
    expiry: u64,
    owner: String,
    cypher: String, // encrypted
}
```

### CypherPost Fields

- id: 
    Unique id for this post given by the server.

- genesis: 
    Unix timestamp of when the post was created.

- expiry: 
    Unix timestamp of when the post will be removed from the server.

- owner: 
    The post owner's pubkey

- cypher: 
    Encrypted stringified json data model 
    
    It is meant for the recipient to verify the checksum of their decrypted payload.
   
## Client model

When making a `post` to the server, the client first constructs a Post type - then stringifies it and encrypts it as `cypher`.

When retreiving the ServerPostModel, the client decrypts its `cypher` and creates a LocalPostModel to store and use locally.

At the top most level, a LocalPostModel is the same as the ServerPostModel, with `post` instead of `cypher`.

Post data contained under the `post` field is only known to the client.

```rust
LocalPostModel{
    id: String,
    genesis: u64,
    expiry: u64,
    owner: String,
    // The above fields are the same as ServerPostModel
    post: Post {
        to: Recipient {
            Direct(pubkey: String),
            Group(id: String),
        },
        payload: Payload {
            Ping, // All contracts start with a ping
            ChecksumPong(checksum: String), // All pings responded with pong and checksum proof.
            Message(text: String),
            Quote(quote: Quotation),  // quote an exchange rate
            Confirm(reference: String), // thumbs up another post
            Reject(reference: String), // thumbs down another post
            Comment(reference: String, text: String), // comment on another post
            PolicyXpub(xpub: PolicyXpub),
            Address(address: WalletAddress),
            Psbt(psbt: WalletPsbt),
            Document(doc: std::file::File),
            Jitsi(url: String),
            Custom(item: T::<impl IntoHash>)
        },
        checksum: String,
        signature : String,
    },

}
```

### Post Fields

- to: 
    A classification of the Payload based on who its indended recipients are. 

- payload: 
    The core contents of your post.

- checksum: 
    An md5 checksum of the Payload.
    Format for <impl IntoString>: `md5($to:$payload)`
    Format for <impl File>: `md5(md5($to):md5($payload)))`

- signature: 
    Prove the authenticity of the owner. 
    The ability to decrypt a post given by the server is not sufficient to verify its origin with the owner.
    Format: `sign($checksum)`


Payload sub structures:

```rust

Quotation{
    base: FiatUnit{
        INR,
        Custom(symbol: String)
    },
    source_url: String,
    source_rate: u64,
    insurance: f64, // escrow base fees
    dispute: f64, // escrow dispute fees, shared by maker and taker in case of dispute
    margin: f64, // maker margin
    price: u64, // your final quote
}

PolicyXPub{
    label: String,
    value: bitcoin::*::ExtendedPubkey
}

WalletAddress {
    label: String,
    index: u64,
    value: bitcoin::*::Address
}

WalletPsbt {
    label: String,
    value: bitcoin::*::PartiallySignedTransaction
}

```

All wallet sub structures have the following minimum fields:

- label:
    Used to link to a wallet

- value: 
    The actual payload material


## Operations

### SEND 
- Create something of `value`. Your private message.
- Give it a `label`.
- Calculate its `checksum` to allow verification of its integrity.
- Your Payload is now ready!
- Add a group to this Post or use None.
- Sign the Payload.
- Derive a new secret from your master key to encrypt your Post (+ keeping track of derivation paths)
- Stringify the Post
- Encrypt the stringified Post with the `encryption_key`
- POST to /v2/post the `cypher` and get back a unique Post `id`
- List who you want to share this post as  `recipients`
- Map the List & Encrypt the `encryption_key` for each recipient using ECDH Shared Secret and collect them as a List as `decryption_keys`
- POST /v2/post/keys the `decryption_keys` and get back a confirmation.
- SEND /v3/notifications the Post `id` to your `recipients` so they can fetch the exact CypherPost.

### RECEIVE
- GET /v2/post/self List of CypherPost and 
    decrypt for each `cypher` into `post` using `derivation_scheme`
        verify Payload `checksum` and Post `signature` 
    then create `my_posts` as a List of PlainPost  
- GET /v2/post/others List of CypherPost and 
    decrypt for each `cypher` into `post` using ECDH `shared_secret`
        verify Payload `checksum` and Post `signature` 
    then create `others_posts` a List of PlainPost
- Merge the two Lists and sort them by `genesis`.
- Separate the Posts based on `y` -> Direct or Group.
- Merge and Store the result with the existing.
- Maintain the `genesis` value of the last entry and use it as the `genesis_filter` for successive GET requests to cypherpost
