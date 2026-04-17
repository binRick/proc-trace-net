# proc-trace-net

**See every network connection on your Linux system — in real time, with PID, process name, direction, and close timing.**

`proc-trace-net` listens to the Linux kernel's [conntrack](https://conntrack-tools.netfilter.org/) subsystem via a netlink socket and prints a line every time any process opens or closes a TCP or UDP connection. No eBPF, no `ptrace`, no kernel module — just a netlink socket and `/proc`.

---

## Features

- **System-wide**: every TCP/UDP connection on the machine, not just your shell's children
- **PID + process name**: correlates each connection to the owning process via `/proc/net/tcp` inode lookup
- **Direction**: distinguishes outbound (`→`) from inbound (`←`) connections
- **Close timing** (`-t`): elapsed duration shown when a connection closes
- **TCP state updates** (`-U`): shows ESTABLISHED, FIN_WAIT, TIME_WAIT, etc.
- **Reverse DNS** (`-r`): async PTR lookup for remote IPs, cached per session
- **Subtree filter** (`-p PID`): watch only connections of one process and its descendants
- **CMD mode**: `proc-trace-net CMD...` runs a command and traces only its connections
- **Single static binary**, zero runtime dependencies

---

## Requirements

- Linux kernel with `CONFIG_NF_CONNTRACK=y` — standard on any distro running Docker, iptables, or nftables
- Root or `CAP_NET_ADMIN`

---

## Build

### Docker — no local Go install needed

```bash
chmod +x build.sh
./build.sh
# → binaries in ./dist/
#   proc-trace-net-linux-amd64
#   proc-trace-net-linux-arm64
```

### From source

```bash
go build -o proc-trace-net .
```

### Static binary

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o proc-trace-net .
```

---

## Usage

```
proc-trace-net [-ctUurQ46] [-o FILE] [-p PID[,PID,...] | CMD...]
```

### Watch all connections system-wide

```bash
sudo proc-trace-net -ctu
```

```
 1234 curl         TCP  10.0.2.15:54321          → 93.184.216.34:443
 5678 sshd         TCP  10.0.2.15:22             ← 203.0.113.7:41002
 9012 systemd-r    UDP  10.0.2.15:46012          → 8.8.8.8:53
```

### Trace a command and all of its connections

```bash
sudo proc-trace-net -ctr curl https://example.com
```

```
 84231 curl         TCP  10.0.2.15:55104          → 93.184.216.34:443     [example.com]
```

### Watch with close events and timing

```bash
sudo proc-trace-net -ct
```

```
 84231 curl         TCP  10.0.2.15:55104          → 93.184.216.34:443
 84231 curl         TCP  10.0.2.15:55104          × 93.184.216.34:443     0.342s
```

### Show TCP state transitions

```bash
sudo proc-trace-net -cU
```

```
 84231 curl         TCP  10.0.2.15:55104          → 93.184.216.34:443
 84231 curl         TCP  10.0.2.15:55104          ⇒ 93.184.216.34:443     ESTABLISHED
 84231 curl         TCP  10.0.2.15:55104          ⇒ 93.184.216.34:443     FIN_WAIT
```

### Watch only the connections of an existing process and its children

```bash
sudo proc-trace-net -p $(pgrep nginx | paste -sd,)
```

### Log everything to a file

```bash
sudo proc-trace-net -Qo /var/log/connections.log &
```

---

## Flags

| Flag | Description |
|------|-------------|
| `-c` | Colorize output (auto-detected when stdout is a tty) |
| `-t` | Show connection close events with elapsed duration |
| `-U` | Show TCP state update events (ESTABLISHED, FIN_WAIT, …) |
| `-u` | Print owning user of each connection |
| `-r` | Reverse DNS lookup for remote IPs (async, cached) |
| `-4` | IPv4 connections only |
| `-6` | IPv6 connections only |
| `-o FILE` | Write output to FILE instead of stdout |
| `-p PID` | Only trace connections of PID and its descendants (comma-separate for multiple) |
| `-Q` | Suppress error messages |

---

## Output format

```
  PID  COMM         PROTO  SRC_IP:PORT              DIR  DST_IP:PORT              [extra]
```

| Symbol | Meaning |
|--------|---------|
| `→` | Outbound connection (local process initiated) |
| `←` | Inbound connection (remote host connected to local service) |
| `↔` | Direction unknown (PID lookup missed the race) |
| `⇒` | TCP state update (with `-U`) |
| `×` | Connection closed (with `-t`) |

The `[extra]` column shows:
- Reverse DNS hostname (with `-r`)
- TCP state name for update events (with `-U`)
- Elapsed time for close events (with `-t`)

---

## How it works

Linux tracks every TCP and UDP connection through the conntrack subsystem (`nf_conntrack`). Conntrack publishes real-time events over a netlink socket (`AF_NETLINK` / `NETLINK_NETFILTER`, multicast groups `NF_NETLINK_CONNTRACK_NEW` and `NF_NETLINK_CONNTRACK_DESTROY`). Any process holding `CAP_NET_ADMIN` can subscribe and receive a message for every new or closed connection, system-wide.

On each **NEW** event:

1. Parse the `CTA_TUPLE_ORIG` nested netlink attributes to extract src/dst IP, port, and protocol
2. Read `/proc/net/tcp` (or `tcp6`/`udp`/`udp6`) to find the socket inode matching this connection
3. Scan `/proc/<pid>/fd/` symlinks system-wide for `socket:[inode]` to identify the owning PID
4. Read `/proc/<pid>/comm` for the process name
5. Store the entry (PID, comm, direction, start time) in an in-memory map keyed by the connection tuple
6. Print the formatted line

On each **DESTROY** event: look up the stored entry, compute elapsed time, print the close line (with `-t`), and remove it from the map.

On **UPDATE** events (with `-U`): parse `CTA_PROTOINFO_TCP_STATE` from the message to extract the new TCP conntrack state and print it.

**PID correlation race**: conntrack events fire at the kernel level; the inode → PID scan happens in userspace immediately after. For very short-lived connections this lookup may miss. For all normal connections (web requests, SSH, DNS) it succeeds reliably.

**Ancestry filtering** (`-p`): PID filter walks the `/proc/<pid>/stat` parent chain upward until it finds a watched PID or reaches PID 1, same approach as `proc-trace-exec`.
