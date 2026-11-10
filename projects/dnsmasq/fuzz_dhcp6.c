/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "fuzz_header.h"

/* each harness is its own binary, so it needs its own copy of this symbol
   (no-op is fine under -detect_leaks=0) */
void fuzz_blockdata_cleanup(void) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1)
    return 0;

  gb_init();

  int succ = init_daemon(&data, &size);   /* minimal empty-config daemon */

  if (succ == 0) {
    static int once = 0;
    if (!once) { cache_init(); blockdata_init(); once = 1; }

    /* Server DUID. Real servers always have one. dhcp6_no_relay copies it into
       every reply's SERVER_ID option, and REQUEST/RENEW/RELEASE/DECLINE require
       an incoming server-id that matches it -- so a fixed DUID lets seeds for
       those message types reach allocation too. (SOLICIT needs no server-id.)
       DUID-LL: type 0x0003, hwtype 0x0001, then a 6-byte link-layer address. */
    if (!daemon->duid) {
      static const unsigned char srv_duid[10] =
        { 0,3, 0,1, 0xde,0xad,0xbe,0xef,0x00,0x01 };
      daemon->duid = (unsigned char *)gb_alloc_data(sizeof(srv_duid));
      if (daemon->duid) {
        memcpy(daemon->duid, srv_duid, sizeof(srv_duid));
        daemon->duid_len = sizeof(srv_duid);
      }
    }

    /* Minimal valid dynamic DHCPv6 context. Without it state->context == NULL,
       so EVERY `for (c = state->context; ...)` loop and address6_*() call in
       dhcp6_no_relay runs zero times -> SOLICIT/REQUEST stay shallow (which is
       why libFuzzer reduced the rich seeds to tiny ones). A single CONTEXT_DHCP
       range makes address6_allocate/available, build_ia, add_address and
       calculate_times do real work. SOLICIT exercises all of that but leaves
       state->lease_allocate == 0, so update_leases() (the lease subsystem) is
       NOT touched -- keeping this first depth step self-contained. */
    struct dhcp_context *ctx = (struct dhcp_context *)gb_alloc_data(sizeof(struct dhcp_context));
    if (ctx) {
      ctx->flags = CONTEXT_DHCP;        /* real dynamic range, not STATIC/TEMPLATE/RA */
      ctx->prefix = 64;
      ctx->valid = ctx->preferred = 0xffffffff;
      ctx->lease_time = 3600;
      ctx->current = ctx->next = NULL;
      ctx->filter = NULL;
      ctx->netid.net = NULL;            /* no context tag */
      ctx->netid.next = &ctx->netid;    /* "unused" sentinel (matches reset loop) */
      /* range 2001:db8::1 .. 2001:db8::ffff, all inside one /64 */
      inet_pton(AF_INET6, "2001:db8::1",    &ctx->start6);
      inet_pton(AF_INET6, "2001:db8::ffff", &ctx->end6);
      ctx->local6 = ctx->start6;
      daemon->dhcp6 = ctx;              /* relay/daemon->dhcp6 iterations see it too */
    }

    if (size > 4) {   /* dhcp6_reply returns early on sz <= 4 */
      /* Faithful packet buffer. Production receives into daemon->dhcp_packet,
         which is never smaller than sizeof(struct dhcp_packet) (~548B) and only
         grows -> a short packet always has trailing slack in the real daemon.
         Mirror that: allocate max(sizeof(struct dhcp_packet), size) but still
         pass sz = size. A packet LARGER than that can legitimately have zero
         slack in production (modern-kernel exact-fit recv path), so we do NOT
         pad past it -- genuine large tail over-reads stay detectable.
         (A tight malloc(size) was over-strict: it fired finding #1, a benign
         1-byte FQDN read that small packets can't reach in production.) */
      size_t bufsz = size < sizeof(struct dhcp_packet) ? sizeof(struct dhcp_packet) : size;
      unsigned char *pkt = (unsigned char *)malloc(bufsz);
      if (pkt) {
        memset(pkt, 0, bufsz);
        memcpy(pkt, data, size);
        pointer_arr[pointer_idx++] = (void *)pkt;

        /* dhcp6_reply reads the packet from daemon->dhcp_packet */
        struct iovec iov;
        iov.iov_base = pkt;
        iov.iov_len = size;
        daemon->dhcp_packet = iov;

        /* scratch interface name + zeroed address args */
        char *ifname = gb_alloc_data(IF_NAMESIZE);
        if (ifname) {
          memcpy(ifname, "eth0", 5);

          struct in6_addr fallback, ll_addr, ula_addr, client_addr;
          memset(&fallback, 0, sizeof(fallback));
          memset(&ll_addr, 0, sizeof(ll_addr));
          memset(&ula_addr, 0, sizeof(ula_addr));
          memset(&client_addr, 0, sizeof(client_addr));

          time_t now = 0;
          dhcp6_reply(ctx,             /* context (NULL if alloc failed) */
                      1,               /* multicast_dest */
                      1,               /* interface */
                      ifname,
                      &fallback, &ll_addr, &ula_addr,
                      size,            /* sz        */
                      &client_addr,
                      now);
        }
      }
    }

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  /* daemon->outpacket is where dhcp6 builds its reply; it grows via expand_buf()
     -> realloc() and is NOT tracked by the gb allocator, so gb_cleanup() won't
     free it. Each run makes a fresh daemon, orphaning the previous buffer ->
     steady RSS climb -> libFuzzer OOM. Free it here while daemon is still alive
     (free is #define'd to free_real, which reads daemon->log_malloc). */
  if (daemon && daemon->outpacket.iov_base) {
    free(daemon->outpacket.iov_base);
    daemon->outpacket.iov_base = NULL;
    daemon->outpacket.iov_len = 0;
  }

  gb_cleanup();
  return 0;
}
