# Packet Sender

A utility for sending arbitrary packets.

# Usage

```
$ packet-sender --help

Send packets
Usage: packet-sender [-i|--intf INTF] [-v|--verbose] [-n|--dry-run] COMMAND
Available options:
  -h,--help                Show this help text
  -i,--intf INTF           Network interface to send on (default: "lo")
  -v,--verbose             Print the packet contents to stdout before sending
  -n,--dry-run             Don't actually send the packet, just print it
Available commands:
  ether                    Send ethernet packet
  raw                      Raw payload
```

# Data expressions

Raw packet data can be specified with simple expressions.

## Raw hex

```
$ packets-sender -n raw 0123456789abcde

Length: 8 (0x8) bytes
0000:   01 23 45 67  89 ab cd ef                             .#Eg....
```

## Replication

```
$ packet-sender -n raw "64 * aa"

Length: 64 (0x40) bytes
0000:   aa aa aa aa  aa aa aa aa  aa aa aa aa  aa aa aa aa   ................
0010:   aa aa aa aa  aa aa aa aa  aa aa aa aa  aa aa aa aa   ................
0020:   aa aa aa aa  aa aa aa aa  aa aa aa aa  aa aa aa aa   ................
0030:   aa aa aa aa  aa aa aa aa  aa aa aa aa  aa aa aa aa   ................
```

## Numbers with specified width and base 

```
$ packet-sender -n raw "16#d12345678"

Length: 16 (0x10) bytes
0000:   00 00 00 00  00 00 00 00  00 00 00 00  00 bc 61 4e   ..............aN
```

## ASCII strings


```
$ packet-sender -n raw "'abcdefghijkl'"

Length: 12 (0xc) bytes
0000:   61 62 63 64  65 66 67 68  69 6a 6b 6c                abcdefghijkl
```

## Combining with concatenation and parentheses

```
$ packet-sender -n raw "'abcdefghijkl' 5 * (2#d10 abab)"

Length: 32 (0x20) bytes
0000:   61 62 63 64  65 66 67 68  69 6a 6b 6c  00 0a ab ab   abcdefghijkl....
0010:   00 0a ab ab  00 0a ab ab  00 0a ab ab  00 0a ab ab   ................
```

# Protocols

```
$ packet-sender -n ether -s aa:aa:aa:aa:aa:aa ip -s 12.12.12.12 -l 28 udp -l 8 "'aaaaaa'"

Length: 48 (0x30) bytes
0000:   ff ff ff ff  ff ff aa aa  aa aa aa aa  08 00 45 00   ..............E.
0010:   00 1c 00 00  00 00 00 11  00 00 0c 0c  0c 0c 7f 00   ................
0020:   00 01 00 00  00 00 00 08  00 00 61 61  61 61 61 61   ..........aaaaaa
```

