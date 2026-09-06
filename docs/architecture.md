# ptype-watch — arquitectura

Inspector C++23 stdlib-only de dos archivos de `/proc/net` relacionados con
la capa 2:

```
/proc/net/ptype     packet_type_seq_show   registro de handlers ETH_P_*
        │
        ▼
   PtypeEntry {type, device, function, module}
        │
        ▼
   decode ethertype 0800→IPv4, 86dd→IPv6, 0003→ALL, ...
        │
/proc/net/packet    packet_seq_show        sockets AF_PACKET (tcpdump, …)
        │
        ▼
   PacketSock {sk, refcnt, sock_type, proto, ifindex, running, rmem, uid, inode}
        │
        ▼
   Snapshot  →  --stats / --types / --sockets / --json / --watch
```

## Formato kernel

`packet_type_seq_show` imprime `%04x %-8s %ps`:

- `type` en host-endian ya pasado por `ntohs` (4 hex).
- `device` vacío = wildcard (todas las ifaces); si hay nombre, el handler
  está ligado a esa iface.
- `function` es `%ps` (nombre del símbolo); si el handler vive en un
  módulo, el kernel añade ` [modulo]`.

`packet_seq_show` imprime pointer, refcnt, `sk_type`, proto (`ntohs(po->num)`),
`sk_bound_dev_if`, running, rmem, uid, inode. `Iface 0` = no bound
(`PACKET_FANOUT` / captura global). `Type 3` = `SOCK_RAW`, `2` = `SOCK_DGRAM`.

## Decisiones

- Paleta ANSI **mutable**: `--no-color` vacía los strings, no es un no-op.
- `--file` salta `#` hasta fin de línea y líneas en blanco (el dump de
  muestra del README lleva comentarios).
- `--watch N` hace `std::cout << std::flush` en cada frame (pipes).
- JSON con claves **siempre citadas**; se valida con `json.load`.
- Demo embebido: host con IPv4/IPv6/ARP/VLAN/LLDP/PTP + 3 sockets AF_PACKET.

## Build

```
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ptype-watch
```
