// SPDX-License-Identifier: MIT
// cpp-ptype-watch — packet type registry + AF_PACKET socket inspector (/proc/net/ptype + packet)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o ptype-watch
// Usage: ./ptype-watch [options]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
struct PtypeEntry {
  int type = 0;             // ethertype (host order, already ntohs'd by kernel)
  std::string device;       // "" = wildcard (all ifaces)
  std::string function;     // symbol name (%ps)
  std::string module;       // module in square brackets, if any
};

struct PacketSock {
  std::string sk;           // sock pointer (64-bit hex)
  long refcnt = 0;
  int sock_type = 0;        // 3 = SOCK_RAW, 2 = SOCK_DGRAM
  int proto = 0;            // ethertype (host order)
  long ifindex = 0;         // 0 = not bound
  int running = 0;          // 1 = bound to live iface
  long rmem = 0;
  long uid = 0;
  long inode = 0;
};

struct Snapshot {
  long ts = 0;
  std::string ptype_source;   // /proc/net/ptype or demo/file
  std::string packet_source;  // /proc/net/packet or demo/file
  std::vector<PtypeEntry> ptypes;
  std::vector<PacketSock> socks;
  bool demo = false;

  // derived
  int wildcard = 0;         // handlers bound to all ifaces
  int bound = 0;            // handlers bound to a specific iface
  int module_hdrs = 0;      // handlers whose function lives in a module
  int raw_socks = 0;        // SOCK_RAW
  int dgram_socks = 0;      // SOCK_DGRAM
  int bound_socks = 0;      // sockets with ifindex != 0
  long total_rmem = 0;
};

// Linux <linux/if_ether.h> ETH_P_* (subset used by the decoder)
struct EtherName { int type; const char* name; };
static const EtherName kEthers[] = {
  {0x0003, "ALL (promisc catch-all)"},
  {0x0004, "LLC"},
  {0x0006, "TRAILER"},
  {0x0800, "IPv4"},
  {0x0806, "ARP"},
  {0x0835, "RARP"},
  {0x0842, "WOL"},
  {0x22f0, "AVTP"},
  {0x22f3, "TIPC"},
  {0x6003, "DEC"},
  {0x8035, "RARP (reverse)"},
  {0x809B, "Appletalk"},
  {0x80F5, "AARP"},
  {0x8100, "VLAN"},
  {0x8137, "IPX"},
  {0x814C, "SNMP"},
  {0x86DD, "IPv6"},
  {0x8808, "Flow control"},
  {0x8809, "Slow protocols (LACP)"},
  {0x8819, "CobraNet"},
  {0x8847, "MPLS unicast"},
  {0x8848, "MPLS multicast"},
  {0x8863, "PPPoE discovery"},
  {0x8864, "PPPoE session"},
  {0x886F, "LLDP"},
  {0x8884, "ATMP"},
  {0x8892, "PROFINET"},
  {0x88A2, "ATA over Ethernet"},
  {0x88A4, "EtherCAT"},
  {0x88A8, "QinQ"},
  {0x88B5, "Local Experimental"},
  {0x88B6, "AoE"},
  {0x88C7, "PTP"},
  {0x88CC, "LLDP (link-layer discovery)"},
  {0x88E1, "HomePlug"},
  {0x88E5, "MACsec"},
  {0x88F7, "PTP v2"},
  {0x8902, "CFM"},
  {0x892F, "HSR"},
  {0x894F, "NSH"},
  {0x9000, "Loopback"},
  {0x9100, "QinQ (0x9100)"},
  {0x88B8, "L2TP"},
  {0xFAFA, "TI-RPC"},
  {0xFFFF, "ALL (0xffff)"},
};

static std::string_view ether_name(int type) {
  for (const auto& e : kEthers) {
    if (e.type == type) return e.name;
  }
  return "unknown";
}

// ─────────────────────────────────────────────────────────────────────────────
// Small parsing helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
  return std::string(s);
}

static std::optional<long> parse_long(std::string_view s) {
  long v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc() || p != s.data() + s.size()) return std::nullopt;
  return v;
}

static std::optional<int> parse_hex4(std::string_view s) {
  if (s.size() != 4) return std::nullopt;
  int v = 0;
  for (char c : s) {
    int d = 0;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return std::nullopt;
    v = v * 16 + d;
  }
  return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsers
// ─────────────────────────────────────────────────────────────────────────────
// ptype row: "0800          ip_rcv"  |  "8100 eth0     vlan_skb_recv"  |  "88cc          eth_nodev"
static bool parse_ptype_line(const std::string& line, PtypeEntry& e) {
  std::istringstream ss(line);
  std::string type_s, dev_s, fn_s;
  if (!(ss >> type_s)) return false;
  auto t = parse_hex4(type_s);
  if (!t) return false;
  // Positional: device occupies cols 4..11, function cols 12.. (kernel %-8s)
  if (line.size() > 12) {
    dev_s = trim(line.substr(4, 8));
    fn_s = trim(line.substr(12));
  } else {
    std::string rest;
    if (ss >> rest) dev_s = rest;
    if (ss >> fn_s) { /* keep */ }
  }
  if (dev_s.empty() && fn_s.empty()) {
    // fallback: tokenize the tail
    std::vector<std::string> toks;
    std::string tok;
    std::istringstream tail(line.substr(4));
    while (tail >> tok) toks.push_back(tok);
    if (!toks.empty()) fn_s = toks.back();
  }
  e.type = *t;
  e.device = dev_s;
  // module tag: "foo_rcv [llc]" — split into function + module
  e.function = fn_s;
  e.module = "";
  auto br = fn_s.find('[');
  if (br != std::string::npos) {
    e.function = trim(fn_s.substr(0, br));
    e.module = trim(fn_s.substr(br));
  }
  return !e.function.empty() || !e.device.empty();
}

// packet row: "ffff9c0c0a1b2c3d  3      3    0003   0     1 8192   0      18432"
static bool parse_packet_line(const std::string& line, PacketSock& s) {
  std::istringstream ss(line);
  std::string sk, type_s, proto_s;
  long refcnt = -1, ifidx = -1, running = -1, rmem = -1, uid = -1, inode = -1;
  if (!(ss >> sk)) return false;
  if (!(ss >> refcnt)) return false;
  if (!(ss >> type_s)) return false;
  if (!(ss >> proto_s)) return false;
  ss >> ifidx >> running >> rmem >> uid >> inode;
  if (refcnt < 0 || ifidx < 0 || running < 0 || rmem < 0 || uid < 0 || inode < 0) return false;
  auto t = parse_long(type_s);
  auto p = parse_hex4(proto_s);
  if (!t || !p) return false;
  s.sk = sk;
  s.refcnt = refcnt;
  s.sock_type = static_cast<int>(*t);
  s.proto = *p;
  s.ifindex = ifidx;
  s.running = static_cast<int>(running);
  s.rmem = rmem;
  s.uid = uid;
  s.inode = inode;
  return true;
}

static std::vector<std::string> read_lines(const std::string& path, bool tolerate_comments) {
  std::vector<std::string> out;
  std::ifstream f(path);
  if (!f) return out;
  std::string line;
  while (std::getline(f, line)) {
    if (tolerate_comments) {
      auto hash = line.find('#');
      if (hash != std::string::npos) line = line.substr(0, hash);
      line = trim(line);
      if (line.empty()) continue;
    }
    out.push_back(line);
  }
  return out;
}

static void parse_ptypes(const std::vector<std::string>& lines, Snapshot& s) {
  bool first = true;
  for (const auto& line : lines) {
    if (first) { first = false; continue; }  // header
    if (line.empty()) continue;
    if (line.rfind("sk ", 0) == 0) continue;  // packet table header
    PtypeEntry e;
    if (parse_ptype_line(line, e)) {
      s.ptypes.push_back(std::move(e));
    }
  }
}

static void parse_packets(const std::vector<std::string>& lines, Snapshot& s) {
  bool first = true;
  for (const auto& line : lines) {
    if (first) { first = false; continue; }
    if (line.empty()) continue;
    // header of ptype table has no leading hex pointer with 16 hex digits followed by spaces
    if (line.size() > 18 && line[16] == ' ' && line[15] != ' ') {
      // starts with a 16-hex-digit pointer? validate cheaply
      bool hex = std::all_of(line.begin(), line.begin() + 16, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      });
      if (!hex) continue;
      PacketSock sck;
      if (parse_packet_line(line, sck)) s.socks.push_back(std::move(sck));
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo data
// ─────────────────────────────────────────────────────────────────────────────
static void derive(Snapshot& s);  // defined below (loading section)

static void fill_demo(Snapshot& s) {
  s.demo = true;
  s.ptype_source = "demo";
  s.packet_source = "demo";
  {
    std::vector<std::string> lines = {
      "Type Device      Function",
      "0800          ip_rcv",
      "0004          llc_rcv [llc]",
      "0806          arp_rcv",
      "00fa          mctp_pkttype_receive",
      "86dd          ipv6_rcv",
      "8100 eth0     vlan_skb_recv",
      "88cc eth0     eth_nodev",
      "0003          packet_rcv",
      "0806 wlan0    arp_rcv",
      "88f7          ptp_rcv [ptp]",
      "886f          lldp_pdu_rcv",
      "86dd wg0      ipv6_rcv",
    };
    parse_ptypes(lines, s);
  }
  {
    std::vector<std::string> lines = {
      "sk               RefCnt Type Proto  Iface R Rmem   User   Inode",
      "ffff9c0c0a1b2c3d  3      3    0003   0     1 8192   0      18432",
      "ffff9c0c0a1b2c4e  2      2    0800   2     1 4096   1000   19001",
      "ffff9c0c0a1b2c5f  2      3    0806   3     0 0      0      19110",
      "ffff9c0c0a1b2c60  1      3    86dd   1     1 2048   1000   19220",
      "ffff9c0c0a1b2c71  1      2    0003   0     1 6144   0      19333",
    };
    parse_packets(lines, s);
  }
  derive(s);
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading
// ─────────────────────────────────────────────────────────────────────────────
static void derive(Snapshot& s) {
  s.wildcard = s.bound = s.module_hdrs = 0;
  for (const auto& p : s.ptypes) {
    if (p.module.empty() && p.device.empty() && p.type == 0x0003) { /* ALL wildcard is just a wildcard */ }
    if (p.device.empty()) ++s.wildcard; else ++s.bound;
    if (!p.module.empty()) ++s.module_hdrs;
  }
  s.raw_socks = s.dgram_socks = s.bound_socks = 0;
  s.total_rmem = 0;
  for (const auto& k : s.socks) {
    if (k.sock_type == 3) ++s.raw_socks;
    else if (k.sock_type == 2) ++s.dgram_socks;
    if (k.ifindex != 0) ++s.bound_socks;
    s.total_rmem += k.rmem;
  }
}

static bool load_snapshot(Snapshot& s, bool demo) {
  if (demo) { fill_demo(s); return true; }
  auto pl = read_lines("/proc/net/ptype", false);
  auto pk = read_lines("/proc/net/packet", false);
  if (pl.size() < 2) return false;   // header + at least nothing; still ok if empty table
  parse_ptypes(pl, s);
  parse_packets(pk, s);
  s.ptype_source = "/proc/net/ptype";
  s.packet_source = "/proc/net/packet";
  derive(s);
  return true;
}

static bool load_snapshot_file(Snapshot& s, const std::string& path) {
  auto lines = read_lines(path, true);
  if (lines.size() < 2) return false;
  // Split: first header decides the table
  if (lines[0].rfind("Type", 0) == 0) {
    parse_ptypes(lines, s);
    // try to find a second table (sk ...) in the same file
    parse_packets(lines, s);
  } else if (lines[0].rfind("sk ", 0) == 0) {
    parse_packets(lines, s);
  } else {
    return false;
  }
  s.ptype_source = path;
  s.packet_source = path;
  derive(s);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────
static std::string fmt_rmem(long bytes) {
  if (bytes >= 1'048'576) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.1f MiB", bytes / 1048576.0);
    return b;
  }
  if (bytes >= 1024) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.1f KiB", bytes / 1024.0);
    return b;
  }
  return std::to_string(bytes) + " B";
}

static const char* sock_type_name(int t) {
  switch (t) {
    case 3: return "SOCK_RAW";
    case 2: return "SOCK_DGRAM";
    default: return "?";
  }
}

static void render_stats(const Snapshot& s) {
  std::cout << C_BOLD << "-- packet type registry (" << s.ptype_source << ") --" << C_RESET << "\n";
  std::cout << C_DIM << "  " << s.ptypes.size() << " handlers  " << C_RESET
            << C_DIM << s.wildcard << " wildcard  " << C_RESET
            << C_DIM << s.bound << " iface-bound  " << C_RESET
            << C_DIM << s.module_hdrs << " in modules" << C_RESET << "\n";
  std::cout << C_BOLD << "-- AF_PACKET sockets (" << s.packet_source << ") --" << C_RESET << "\n";
  std::cout << C_DIM << "  " << s.socks.size() << " sockets  " << C_RESET
            << C_GREEN << s.raw_socks << " raw  " << C_RESET
            << C_CYAN << s.dgram_socks << " dgram  " << C_RESET
            << C_DIM << s.bound_socks << " bound  " << C_RESET
            << C_YELLOW << "rmem " << fmt_rmem(s.total_rmem) << C_RESET << "\n";
}

static void render_types(const Snapshot& s, int top) {
  int shown = 0;
  std::cout << C_BOLD << "  TYPE  " << C_RESET << C_DIM << "IFACE      " << C_RESET
            << C_DIM << "FUNCTION            " << C_RESET << C_DIM << "PROTOCOL" << C_RESET << "\n";
  for (const auto& p : s.ptypes) {
    if (top > 0 && shown >= top) break;
    char type_buf[8];
    std::snprintf(type_buf, sizeof(type_buf), "%04x", p.type);
    std::string dev = p.device.empty() ? "*" : p.device;
    char row[160];
    std::snprintf(row, sizeof(row), "  %s  %-10s %-19s %s",
                  type_buf, dev.c_str(), p.function.c_str(),
                  std::string(ether_name(p.type)).c_str());
    // colorize by family
    std::string_view fam = ether_name(p.type);
    std::string color = C_RESET;
    if (fam == "IPv4") color = C_GREEN;
    else if (fam == "IPv6") color = C_CYAN;
    else if (fam == "ARP") color = C_YELLOW;
    else if (p.type == 0x0003) color = C_MAGENTA;
    else if (p.type == 0x8100 || p.type == 0x88A8 || p.type == 0x9100) color = C_RED;
    else if (!p.module.empty()) color = C_DIM;
    std::cout << color << row << C_RESET;
    if (!p.module.empty()) std::cout << " " << C_DIM << p.module << C_RESET;
    std::cout << "\n";
    ++shown;
  }
  if (top > 0 && static_cast<size_t>(shown) < s.ptypes.size()) {
    std::cout << C_DIM << "  … " << (s.ptypes.size() - shown) << " more (--all)\n" << C_RESET;
  }
}

static void render_sockets(const Snapshot& s, int top) {
  std::cout << C_BOLD << "  SOCKET            " << C_RESET << C_DIM << "REF " << C_RESET
            << C_DIM << "TYPE       " << C_RESET << C_DIM << "PROTO " << C_RESET
            << C_DIM << "IFACE " << C_RESET << C_DIM << "R  " << C_RESET
            << C_DIM << "RMEM     " << C_RESET << C_DIM << "USER  " << C_RESET
            << C_DIM << "INODE" << C_RESET << "\n";
  int shown = 0;
  for (const auto& k : s.socks) {
    if (top > 0 && shown >= top) break;
    char proto_buf[8];
    std::snprintf(proto_buf, sizeof(proto_buf), "%04x", k.proto);
    char iface_buf[16];
    std::snprintf(iface_buf, sizeof(iface_buf), "%ld", k.ifindex);
    char rmem_buf[16];
    std::snprintf(rmem_buf, sizeof(rmem_buf), "%ld", k.rmem);
    char user_buf[16];
    std::snprintf(user_buf, sizeof(user_buf), "%ld", k.uid);
    std::string type = sock_type_name(k.sock_type);
    std::cout << C_DIM << "  " << k.sk << "  " << C_RESET
              << C_YELLOW << std::setw(3) << k.refcnt << "  " << C_RESET
              << C_CYAN << std::left << std::setw(10) << type << C_RESET << " "
              << C_GREEN << std::setw(6) << proto_buf << C_RESET << " "
              << C_MAGENTA << std::setw(5) << iface_buf << C_RESET << " "
              << (k.running ? C_GREEN : C_DIM) << (k.running ? "Y " : "N ") << C_RESET
              << C_DIM << std::setw(9) << rmem_buf << C_RESET
              << C_DIM << std::setw(6) << user_buf << C_RESET
              << C_DIM << k.inode << C_RESET
              << C_DIM << "  (" << ether_name(k.proto) << ")" << C_RESET << "\n";
    ++shown;
  }
}

static void render_json(const Snapshot& s) {
  std::cout << "{\n";
  std::cout << "  \"summary\": {\n";
  std::cout << "    \"handlers\": " << s.ptypes.size() << ",\n";
  std::cout << "    \"wildcard\": " << s.wildcard << ",\n";
  std::cout << "    \"iface_bound\": " << s.bound << ",\n";
  std::cout << "    \"module_handlers\": " << s.module_hdrs << ",\n";
  std::cout << "    \"sockets\": " << s.socks.size() << ",\n";
  std::cout << "    \"raw\": " << s.raw_socks << ",\n";
  std::cout << "    \"dgram\": " << s.dgram_socks << ",\n";
  std::cout << "    \"bound_sockets\": " << s.bound_socks << ",\n";
  std::cout << "    \"rmem_bytes\": " << s.total_rmem << ",\n";
  std::cout << "    \"source\": \"" << (s.demo ? "demo" : "/proc/net") << "\",\n";
  std::cout << "    \"timestamp\": " << s.ts << "\n";
  std::cout << "  },\n";
  std::cout << "  \"ptypes\": [\n";
  for (size_t i = 0; i < s.ptypes.size(); ++i) {
    const auto& p = s.ptypes[i];
    char tb[8];
    std::snprintf(tb, sizeof(tb), "%04x", p.type);
    std::cout << "    {\"type\": \"" << tb << "\", \"name\": \"" << ether_name(p.type)
              << "\", \"device\": \"" << p.device << "\", \"function\": \"" << p.function
              << "\", \"module\": \"" << p.module << "\"}";
    if (i + 1 < s.ptypes.size()) std::cout << ",";
    std::cout << "\n";
  }
  std::cout << "  ],\n";
  std::cout << "  \"sockets\": [\n";
  for (size_t i = 0; i < s.socks.size(); ++i) {
    const auto& k = s.socks[i];
    char pb[8];
    std::snprintf(pb, sizeof(pb), "%04x", k.proto);
    std::cout << "    {\"sk\": \"" << k.sk << "\", \"refcnt\": " << k.refcnt
              << ", \"sock_type\": " << k.sock_type << ", \"proto\": \"" << pb
              << "\", \"ifindex\": " << k.ifindex << ", \"running\": " << k.running
              << ", \"rmem\": " << k.rmem << ", \"uid\": " << k.uid
              << ", \"inode\": " << k.inode << "}";
    if (i + 1 < s.socks.size()) std::cout << ",";
    std::cout << "\n";
  }
  std::cout << "  ]\n";
  std::cout << "}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0;
static int g_fail = 0;
static void t_check(bool ok, const char* what) {
  if (ok) { ++g_pass; }
  else { ++g_fail; std::cout << C_RED << "  FAIL " << what << C_RESET << "\n"; }
}

static int run_selftest() {
  std::cout << "-- selftest: model + decoder --\n";
  t_check(ether_name(0x0800) == "IPv4", "ether 0800 -> IPv4");
  t_check(ether_name(0x86dd) == "IPv6", "ether 86dd -> IPv6");
  t_check(ether_name(0x0806) == "ARP", "ether 0806 -> ARP");
  t_check(ether_name(0x0003) == "ALL (promisc catch-all)", "ether 0003 -> ALL");
  t_check(ether_name(0x1234) == "unknown", "unknown ethertype");
  t_check(ether_name(0x88f7) == "PTP v2", "ether 88f7 -> PTP v2");
  t_check(ether_name(0x886f) == "LLDP", "ether 886f -> LLDP");

  std::cout << "-- selftest: ptype parser --\n";
  {
    PtypeEntry e;
    t_check(parse_ptype_line("0800          ip_rcv", e), "plain handler row parses");
    t_check(e.type == 0x0800, "type 0800");
    t_check(e.device.empty(), "device empty (wildcard)");
    t_check(e.function == "ip_rcv", "function ip_rcv");
    t_check(e.module.empty(), "no module");
  }
  {
    PtypeEntry e;
    t_check(parse_ptype_line("0004          llc_rcv [llc]", e), "module row parses");
    t_check(e.type == 0x0004, "type 0004");
    t_check(e.function == "llc_rcv", "function llc_rcv");
    t_check(e.module == "[llc]", "module [llc]");
  }
  {
    PtypeEntry e;
    t_check(parse_ptype_line("8100 eth0     vlan_skb_recv", e), "bound row parses");
    t_check(e.type == 0x8100, "type 8100 (VLAN)");
    t_check(e.device == "eth0", "device eth0");
  }
  {
    PtypeEntry e;
    t_check(!parse_ptype_line("not-a-valid-row", e), "garbage rejected");
  }

  std::cout << "-- selftest: packet parser --\n";
  {
    PacketSock s;
    bool ok = parse_packet_line("ffff9c0c0a1b2c3d  3      3    0003   0     1 8192   0      18432", s);
    t_check(ok, "socket row parses");
    t_check(s.sk == "ffff9c0c0a1b2c3d", "sk pointer");
    t_check(s.refcnt == 3, "refcnt 3");
    t_check(s.sock_type == 3, "SOCK_RAW");
    t_check(s.proto == 0x0003, "proto 0003 (ALL)");
    t_check(s.ifindex == 0, "ifindex 0 (unbound)");
    t_check(s.running == 1, "running 1");
    t_check(s.rmem == 8192, "rmem 8192");
    t_check(s.uid == 0, "uid 0");
    t_check(s.inode == 18432, "inode 18432");
  }
  {
    PacketSock s;
    bool ok = parse_packet_line("ffff9c0c0a1b2c4e  2      2    0800   2     1 4096   1000   19001", s);
    t_check(ok, "dgram row parses");
    t_check(s.sock_type == 2, "SOCK_DGRAM");
    t_check(s.proto == 0x0800, "proto 0800");
    t_check(s.ifindex == 2, "ifindex 2");
    t_check(!parse_packet_line("garbage here", s), "garbage rejected");
  }

  std::cout << "-- selftest: demo coherence --\n";
  {
    Snapshot s;
    s.ts = 1'700'000'000;
    fill_demo(s);
    t_check(s.ptypes.size() == 12, "demo has 12 handlers");
    t_check(s.socks.size() == 5, "demo has 5 sockets");
    t_check(s.wildcard == 8, "demo wildcard count");
    t_check(s.bound == 4, "demo bound count");
    t_check(s.module_hdrs == 2, "demo module handlers");
    t_check(s.raw_socks == 3, "demo raw sockets");
    t_check(s.dgram_socks == 2, "demo dgram sockets");
    t_check(s.bound_socks == 3, "demo bound sockets");
    t_check(s.total_rmem == 8192 + 4096 + 0 + 2048 + 6144, "demo rmem total");
    bool has_vlan = false, has_ipv4 = false;
    for (const auto& p : s.ptypes) {
      if (p.type == 0x8100) has_vlan = true;
      if (p.type == 0x0800 && p.device.empty()) has_ipv4 = true;
    }
    t_check(has_vlan && has_ipv4, "demo key handlers present");
  }

  std::cout << "-- selftest: /proc real --\n";
  {
    Snapshot s;
    bool ok = load_snapshot(s, false);
    t_check(ok, "/proc/net/ptype opens");
    if (ok) {
      t_check(!s.ptypes.empty(), "host has ptype handlers");
      // packet_rcv (0003) only appears while an AF_PACKET socket is open;
      // the stable markers on a busier host are ip_rcv (0800) and ipv6_rcv (86dd)
      bool has_ip = false;
      for (const auto& p : s.ptypes) if (p.type == 0x0800 || p.type == 0x86dd) has_ip = true;
      t_check(has_ip, "L3 handlers (0800/86dd) registered on host");
      // socket table may be empty (no tcpdump running) — only require parseability
      t_check(s.socks.size() <= 100, "sockets table sane");
    }
  }

  std::cout << "-- selftest: file with comments --\n";
  {
    Snapshot s;
    bool ok = load_snapshot_file(s, "sample-ptype.table");
    t_check(ok, "sample file loads");
    if (ok) {
      t_check(s.ptypes.size() == 10, "sample has 10 handlers (comments skipped)");
      t_check(s.socks.size() == 3, "sample has 3 sockets");
    }
  }

  std::cout << "-- selftest: JSON hygiene --\n";
  {
    Snapshot s;
    s.ts = 1'700'000'000;
    fill_demo(s);
    std::ostringstream os;
    std::streambuf* old = std::cout.rdbuf(os.rdbuf());
    render_json(s);
    std::cout.rdbuf(old);
    std::string j = os.str();
    t_check(j.find("\"ptypes\"") != std::string::npos, "json has ptypes");
    t_check(j.find("\"sockets\"") != std::string::npos, "json has sockets");
    t_check(j.find("\"type\": \"0800\", \"name\": \"IPv4\"") != std::string::npos, "json fields quoted");
    t_check(j.find("{type:") == std::string::npos, "no unquoted keys");
  }

  std::cout << "-- selftest: --no-color hygiene --\n";
  {
    Snapshot s;
    fill_demo(s);
    disable_color();
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_stats(s);
    render_types(s, 0);
    render_sockets(s, 0);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    t_check(out.find("packet type registry") != std::string::npos, "output has content");
    enable_color();
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "ptype-watch — packet type registry + AF_PACKET sockets (/proc/net/ptype + packet)\n"
    "\n"
    "Usage: ptype-watch [options]\n"
    "\n"
    "  (default)   summary + handler table + socket table\n"
    "  --stats     summary only\n"
    "  --types     handler table only\n"
    "  --sockets   AF_PACKET socket table only\n"
    "  --all       show every handler (no --top cut)\n"
    "  --top N     show first N handlers and sockets\n"
    "  --json      machine-readable output\n"
    "  --demo      synthetic host (12 handlers, 5 sockets)\n"
    "  --file PATH parse a dump (tolerates # comments)\n"
    "  --watch N   refresh every N seconds\n"
    "  --no-color  disable ANSI colors\n"
    "  --selftest  run self-tests and exit\n"
    "  -h, --help  this help\n";
}

enum class Mode { Auto, Stats, Types, Sockets };

int main(int argc, char** argv) {
  bool color_flag = true, demo = false, json = false, all = false;
  int watch = 0, top = 0;
  std::string file;
  Mode mode = Mode::Auto;

  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) { std::cerr << "error: " << name << " requires a value\n"; return std::nullopt; }
      return std::string(argv[++i]);
    };
    if (a == "--stats")        mode = Mode::Stats;
    else if (a == "--types")   mode = Mode::Types;
    else if (a == "--sockets") mode = Mode::Sockets;
    else if (a == "--file")    { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")     { auto v = next(a); if (!v) return 2; top = std::atoi(v->c_str()); }
    else if (a == "--watch")   { auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--demo")    demo = true;
    else if (a == "--json")    json = true;
    else if (a == "--all")     all = true;
    else if (a == "--no-color") color_flag = false;
    else if (a == "--selftest") return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  auto run_once = [&](const Snapshot& snap) {
    if (json) { render_json(snap); return; }
    int t = top;
    bool show_types = mode == Mode::Types || mode == Mode::Auto;
    bool show_socks = mode == Mode::Sockets || mode == Mode::Auto;
    switch (mode) {
      case Mode::Stats: render_stats(snap); break;
      case Mode::Types: render_types(snap, all ? 0 : (t > 0 ? t : 0)); break;
      case Mode::Sockets: render_sockets(snap, t); break;
      case Mode::Auto:
        render_stats(snap);
        std::cout << "\n";
        render_types(snap, all ? 0 : (t > 0 ? t : 12));
        std::cout << "\n";
        render_sockets(snap, t > 0 ? t : 12);
        break;
    }
    (void)show_types; (void)show_socks;
  };

  if (watch > 0) {
    for (;;) {
      Snapshot snap;
      snap.ts = static_cast<long>(std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000);
      bool ok = !file.empty() ? load_snapshot_file(snap, file) : load_snapshot(snap, demo);
      if (!ok) { std::cerr << "error: cannot read packet type sources\n"; return 1; }
      std::cout << "\x1b[2J\x1b[H";
      run_once(snap);
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Snapshot snap;
  snap.ts = static_cast<long>(std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000);
  bool ok = !file.empty() ? load_snapshot_file(snap, file) : load_snapshot(snap, demo);
  if (!ok) { std::cerr << "error: cannot read packet type sources\n"; return 1; }
  run_once(snap);
  return 0;
}