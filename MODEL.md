# Models

cypherpost as a server seeks to do the most minimal work possible to facilitate private e2ee message forwarding for its clients.

The server side data model is minimal and the client's are tasked with Data Modeling and Management.

## Server model

`cypher` with some additional metadata is stored on the server as follows:

```rust
CypherPost{
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

   
## Client model

When making a `post` to the server, the client first constructs a Post type - then stringifies it and encrypts it as `cypher`.

When retreiving a CypherPost from the server, the client decrypts its `cypher` and creates a PlainPost to store and use locally.

At the top most level, a PlainPost is the same as the CypherPost, with `post` instead of `cypher`.

Post data contained under the `post` field is only known to the client.

Clients must follow the same Post type standard for compatibility.

```rust
PlainPost{
    id: String,
    genesis: u64,
    expiry: u64,
    owner: String,
    // The above fields are the same as CypherPost
    post: Post {
        kind: PostKind {
            Ping,
            Message,
            Pubkey,
            AddressIndex,
            Psbt,
        },
        to: Recipient {
            Direct(to: String),
            Group(id: String),
        },
        payload: Payload {
                label : Option<String>,
                value : T::<impl ToString>, // default: String
                checksum: String, // md5(stringify=(value))
        },
        signature : String,
    },
}
```


### Post Fields

- kind: 
    One dimension of classification of the Payload

- to: 
    Another dimension of classification of the Payload based on who its indended recipients are. 

- payload: 
    The actual post contents.

- signature: 
    Proof of the post's authenticity.
    Format: `sign($kind:$to:$payload.label:$payload.checksum)`

### Payload Fields

- label: 
    An open field to be used as a title, name or a reference to link to an external source.
   
    We use this particularly to link a Payload to a local wallet by using the wallet fingerprint as the label.

- value: 
    The core contents of your post.

    Currently supports plain message, an xpub, a bitcoin address or a psbt; as strings. 

    It can support any data structure required that can be stringified.

- checksum: 
    An md5 checksum to verify the integrity of the message.
    Format: `md5($id:$label:$checksum)`


## Operations

### SEND 
- Create something of `value`. Your private message.
- Give it a `label`.
- Calculate its `checksum` to protect its integrity.
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
