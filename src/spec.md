# spec

## key

lotr key generate <username>
lotr key import <username>
lotr key status
lotr key delete <username>

## chat

lotr chat admin_invite <server> <socks5> <secret>
lotr chat register <server> <socks5> <invite_code>
lotr chat sync <server> <socks5?>
lotr chat post <message>

## contract

lotr contract init <label> <policy>
lotr contract sync <label> 
lotr contract info <label>
lotr contract receive <label>
lotr contract send <label> <output>
lotr contract backup <label>
lotr contract recover <label> <descriptor>

## tor
*low priority*

lotr tor start
lotr tor status
lotr tor stop