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

/*
 * Fuzz harness for rrfilter() in src/rrfilter.c -- strips EDNS0 / DNSSEC RRs
 * from a DNS response packet. Mirrors the faithful fuzz_rfc1035 pattern:
 * minimal valid (empty-config) daemon + a fuzzed packet.
 *
 * Why no faithful config is needed: rrfilter() only reads daemon->filter_rr
 * inside RRFILTER_CONF paths (rrfilter.c lines 170/216/233). In RRFILTER_EDNS0
 * and RRFILTER_DNSSEC modes those derefs are short-circuited, and every helper
 * it calls (check_name, check_rrs, skip_name, rrfilter_desc) is a pure packet
 * walker. So the empty daemon that init_daemon() builds is sufficient.
 *
 * rrfilter() only ever SHRINKS the packet (it elides records and compacts them
 * downward), so the packet buffer needs no append-headroom; we allocate a little
 * anyway, for consistency with the other harnesses.
 */

#include "fuzz_header.h"

/* Was defined in the now-deleted fuzz_util.c; restored here so this
   harness links. Per-run blockdata hook; this build runs with
   detect_leaks=0, so a no-op is safe and matches the original. */
void fuzz_blockdata_cleanup(void) {}


static void FuzzRRFilter(const uint8_t **data2, size_t *size2, int mode) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  if (size > sizeof(struct dns_header) + 50) {
    char *new_data = malloc(size + MAXDNAME + RRFIXEDSZ);
    if (new_data == NULL)
      return;
    memset(new_data, 0, size + MAXDNAME + RRFIXEDSZ);
    memcpy(new_data, data, size);
    pointer_arr[pointer_idx++] = (void *)new_data;

    size_t plen = size;                       /* in/out: rrfilter updates it */
    rrfilter((struct dns_header *)new_data, &plen, mode);
  }
}

/*
 * Fuzzer entrypoint.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1)
    return 0;

  gb_init();

  /* first byte selects the filter mode */
  int i = (int)data[0];
  data += 1;
  size -= 1;

  int succ = init_daemon(&data, &size);

  if (succ == 0) {
    static int once = 0;
    if (!once) { cache_init(); blockdata_init(); once = 1; }

    /* Both config-free modes. EDNS0 strips T_OPT from the additional section;
       DNSSEC strips RRSIG/NSEC/NSEC3 from all sections. */
    if ((i & 1) == 0)
      FuzzRRFilter(&data, &size, RRFILTER_EDNS0);
    else
      FuzzRRFilter(&data, &size, RRFILTER_DNSSEC);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  gb_cleanup();
  return 0;
}
