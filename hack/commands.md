Every alert must be signed with three private keys from the network's active key set,
passed with `-signing-keys` (required).

# Info
```
go run publish.go -signing-keys=<key1>,<key2>,<key3> -type=1 -sequence=1
```

# Ban peer
```
go run publish.go -signing-keys=<key1>,<key2>,<key3> -type=5 -sequence=2 -peer=192.168.1.2/24
```

# Unban peer
```
go run publish.go -signing-keys=<key1>,<key2>,<key3> -type=6 -sequence=3 -peer=192.168.1.2/24
```

# Invalidate Block
```
go run publish.go -signing-keys=<key1>,<key2>,<key3> -type=7 -block-hash=<hash> -sequence=4
```

# Set Keys
Note: the keys should be compressed public keys.
```
go run publish.go -signing-keys=<key1>,<key2>,<key3> -type=8 -sequence=5 -pub-keys=<key1>,<key2>,<key3>,<key4>,<key5>
```
