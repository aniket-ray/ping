# PING
A Ping CLI application for MacOS. The CLI app accepts a hostname or an IP address as its argument, then sends ICMP "echo requests" in a loop to the target while receiving "echo reply" messages. It reports loss and RTT times for each sent message.

## Usage
Compile:

```bash
sudo clang ping.cpp -o CompiledFileName
```
Run:

```bash
sudo ./CompiledFileName.out -h [Host OR IPv4] (OPTIONAL) -t [set TTL] -i [set Ping Interval]
```
