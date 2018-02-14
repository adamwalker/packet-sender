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

