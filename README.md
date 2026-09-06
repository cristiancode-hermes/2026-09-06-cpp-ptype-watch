# ptype-watch

Inspector del **registro de packet types** y de los **sockets AF_PACKET** del
kernel Linux en C++23, zero deps.

Lee `/proc/net/ptype` (tabla de handlers `ETH_P_*` registrados con
`dev_add_pack`) y `/proc/net/packet` (sockets AF_PACKET — los que usan
tcpdump, tshark, ping en modo raw…), decodifica los ethertypes y reporta el
estado combinado.

## Features

- **Registro de handlers** (`/proc/net/ptype`): ethertype en hex (host-endian,
  el kernel ya lo pasa por `ntohs`), iface (vacía = wildcard), símbolo `%ps` y
  módulo `[modulo]` cuando el handler vive en un módulo cargado
- **Decoder de ethertypes**: 40+ protocolos conocidos (`0800` IPv4, `86dd`
  IPv6, `0806` ARP, `8100` VLAN, `886f` LLDP, `88f7` PTP, `88cc` LLDP,
  `0003` ALL/promisc…)
- **Sockets AF_PACKET** (`/proc/net/packet`): pointer `sk`, refcnt,
  `SOCK_RAW`/`SOCK_DGRAM`, proto, ifindex (0 = sin bound), running, rmem,
  uid, inode
- **Resumen**: handlers wildcard vs iface-bound vs en módulos; sockets raw vs
  dgram, bound vs sin bound, rmem total
- **Vistas**: `--types`, `--sockets`, `--top N`, `--all`
- **Modo watch (`--watch N`)**: refresh periódico con `flush` por frame
- **Salida JSON (`--json`)**: claves siempre citadas, validable
- **Demo mode (`--demo`)**: host sintético (12 handlers, 5 sockets, eth0 +
  wlan0 + wg0)
- **`--file`**: parsea un dump (tolera comentarios `#` y líneas en blanco)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 58 checks

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ptype-watch
```

## Usage

```bash
# Snapshot único (host real)
./ptype-watch

# Demo (host sintético)
./ptype-watch --demo

# Solo resumen
./ptype-watch --stats

# Solo la tabla de handlers
./ptype-watch --types

# Solo los sockets AF_PACKET
./ptype-watch --sockets

# Top 6 handlers y sockets
./ptype-watch --top 6

# Todos los handlers (sin cortar)
./ptype-watch --all

# JSON
./ptype-watch --json

# Parsear un dump con comentarios
./ptype-watch --file sample-ptype.table --no-color

# Modo watch (cada 2s)
./ptype-watch --watch 2

# Sin colores
./ptype-watch --no-color

# Auto-tests
./ptype-watch --selftest
```

## Data Sources

| Campo | Origen |
|-------|--------|
| handlers `ETH_P_*` (type, iface, función, módulo) | `/proc/net/ptype` (`packet_type_seq_show`) |
| sockets AF_PACKET (sk, refcnt, type, proto, iface, rmem, uid, inode) | `/proc/net/packet` (`packet_seq_show`) |

## Notas

- `packet_rcv` (`0003`, ALL) solo aparece en `/proc/net/ptype` mientras hay
  al menos un socket AF_PACKET abierto (tcpdump, tshark…); los marcadores
  estables de un host son `ip_rcv` (`0800`) e `ipv6_rcv` (`86dd`).
- Los pointers de socket (`ffff…`) cambian en cada arranque / cada socket;
  úsalos solo como identificador de sesión dentro de un snapshot.
- `Iface 0` en `/proc/net/packet` significa socket sin bound (captura
  global o `PACKET_FANOUT`); `R` = `running` (1 = ligado a iface viva).