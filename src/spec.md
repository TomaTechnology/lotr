# spec

## key

lotr key generate
lotr key import
lotr key status
lotr key delete

## chat

lotr chat adminvite <server> <socks5> <secret>
lotr chat register <server> <username> <invite_code>
lotr chat unregister <server> <username>
lotr chat contacts <server> <socks5>
lotr chat sync <server> <socks5?>
lotr chat post <message>

## contract

lotr contract init <name> <policy>
lotr contract sync 
// share pubkey and check if others have shared
lotr contract info
lotr contract receive <label>
lotr contract send <label> <output>
lotr contract sign <label>
lotr contract broadcast <label>

lotr contract backup <label>
lotr contract recover <descriptor>

## tor
*low priority*

lotr tor start
lotr tor status
lotr tor stop