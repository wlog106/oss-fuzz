# dnsmasq fuzzing harnesses (work in progress)

This branch updates the [OSS-Fuzz](https://github.com/google/oss-fuzz) project for
[dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html). It revives the existing
bit-rotted harnesses, reworks `fuzz_dhcp6` so it reaches the DHCPv6 server logic, and
adds a new `fuzz_rrfilter` target.

Author: Hsuan-Hao Hsu

## Targets

| Target | Status | Entry point | Notes |
|---|---|---|---|
| `fuzz_rfc1035` | revived | `answer_request()` | 20 DNS query seeds. Plateaus around 560 features with an empty config. |
| `fuzz_rrfilter` | **new** | `rrfilter()` (EDNS0 / DNSSEC modes) | Config-free. Input is `[mode selector][packet]`. 11 response-packet seeds plus `dns.dict`. |
| `fuzz_dhcp6` | **reworked** | `dhcp6_reply()` | Whole input is a DHCPv6 packet. Now has a DHCPv6 context, ~100× throughput and a seed corpus covering every message type, including relay. |
| `fuzz_dhcp`, `fuzz_auth` | not revived yet | | Still use the shared header, so they build against the fixes below. |

## Shared harness fixes (`fuzz_header.h`)

The 2021 harness code had bit-rotted and produced crashes that were harness bugs, not
dnsmasq bugs.

- **Use-after-free in cleanup.** dnsmasq `#define`s `free` to a wrapper that reads
  `daemon->log_malloc`, so freeing `daemon` before other allocations was a UAF.
  `gb_cleanup` now frees back-to-front, so `daemon` goes last.
- **Unrealistic daemon state.** `init_daemon` now builds a minimal empty-config daemon
  that mirrors `option.c` startup: scratch buffers at their real sizes, all config
  pointers NULL, fixed TTLs. Config is not fuzzed, because config is admin-controlled,
  not attacker-controlled.
- **Per-run leaks leading to OOM.** `cache_init` / `blockdata_init` now run once.
  Buffers that dnsmasq grows with `expand_buf()` (e.g. `daemon->outpacket`) are freed
  explicitly, since the harness allocator doesn't track them.
- **Packet buffers sized like production.** A tight `malloc(size)` caught tail
  over-reads that production's receive-buffer slack absorbs. Packets are now allocated
  the way the real receive path does: DHCPv6 has a `sizeof(struct dhcp_packet)` floor,
  and DNS gets `size + MAXDNAME + RRFIXEDSZ`.

## `fuzz_dhcp6` rework

The existing harness built and ran, but was slow, leaked memory until libFuzzer hit
OOM, and never got past the early exits in the DHCPv6 server code. Changes:

- **Speed.** `get_client_mac()` does a netlink neighbour lookup with 5×100 ms sleeps on
  a miss, which limited the harness to about 2–6 exec/s. `build.sh` stubs it to report
  "not in neighbour cache", which is a real production outcome. This gives about 100×
  more throughput.
- **Depth.** With no DHCPv6 context, all the address-allocation loops run zero times.
  The harness configures one range (`2001:db8::1`–`::ffff`, /64) and a fixed server
  DUID. Seeded REQUEST/RENEW/RELEASE/DECLINE messages carry that DUID so they get past
  the server-id check.
- **Coverage.** Replaying the seed corpus reaches `check_ia` → `build_ia` →
  `address6_allocate` → `add_address` → `add_options`, plus the
  `dhcp6_maybe_relay` recursion for RELAY-FORW.
- **Memory.** The reply buffer `daemon->outpacket` is freed after each run, which
  fixes the steady RSS climb and the OOM.
- **Seeds** are new and ship as `fuzz_dhcp6_seed_corpus.zip`, so `run_fuzzer` loads
  them automatically.

## Finding

`fuzz_dhcp6` (libFuzzer + ASan) found a 1-byte heap out-of-bounds read in the
RFC 4704 Client FQDN option parser (`rfc3315.c`). The loop reads the next label-length
byte before checking that it's inside the option. The read value is never used, so
it's low severity.

- **DHCPv6 copy:** already fixed upstream. It was covered by CVE-2026-93009 and a
  follow-up patch by Dominik Derigs (dnsmasq-discuss, 2026-10-30). I found it
  independently.
- **DHCPv4 copy:** the same loop in `rfc2131.c` (option 81), introduced in 2013, was
  still unfixed. I found it by auditing the DHCPv4 code and sent a patch:
  [dnsmasq-discuss archive link](<ARCHIVE LINK>).

`build.sh` currently applies the DHCPv6 fix via `sed` so the fuzzer doesn't keep
rediscovering it. This gets dropped when the harnesses are upstreamed to OSS-Fuzz.

## Usage

```sh
python3 infra/helper.py build_fuzzers dnsmasq
python3 infra/helper.py run_fuzzer dnsmasq fuzz_dhcp6 -- -detect_leaks=0

# coverage report
python3 infra/helper.py build_fuzzers --sanitizer coverage dnsmasq
python3 infra/helper.py coverage dnsmasq --fuzz-target fuzz_dhcp6 \
  --corpus-dir=<seed dir> --no-corpus-download
```

`-detect_leaks=0` suppresses a known blockdata pool allocation that is not a bug.

Note: `run_fuzzer --corpus-dir` deletes the contents of the directory you pass before
the run. Don't point it at your only copy of a corpus.

## Next steps

- Long fuzzing runs on the DHCPv6 allocation and relay paths
- Prefix delegation (IA_PD) seeds
- Revive `fuzz_dhcp` (DHCPv4) and `fuzz_auth`
- Upstream these changes to OSS-Fuzz
