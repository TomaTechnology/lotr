# spec

## mk

levrem mk generate <username>
levrem mk import <username> <mnemonic> <passphrase?>
levrem mk status <username>
levrem mk drop

## chat

levrem chat admin_invite <server> <socks5> <secret>
levrem chat register <server> <socks5> <invite_code>
levrem chat sync <server> <socks5?>
levrem chat post <message>

## contract

levrem contract init <label> <policy>
levrem contract sync <label> 
levrem contract info <label>
levrem contract receive <label>
levrem contract send <label> <output>
levrem contract backup <label>
levrem contract recover <label> <descriptor>

## tor
*low priority*

levrem tor start
levrem tor status
levrem tor stop