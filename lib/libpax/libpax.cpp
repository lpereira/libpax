/*
LICENSE

Copyright  2020      Deutsche Bahn Station&Service AG
Copyright  2025      Laboratório Hacker de Campinas

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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "globals.h"
#include "libpax.h"

uint8_t channel = 0;  // channel rotation counter

static inline uint32_t fnv1a_32(const void *buffer, size_t len) {
  const unsigned char *data = (unsigned char *)buffer;
  uint32_t hash;

  for (hash = 0x811c9dc5u; len--; data++) {
    hash = (hash ^ *data) * 0x1000193u;
  }

  return hash;
}

static uint16_t hash_mac_address(const uint8_t addr[6]) {
  const uint32_t hash = fnv1a_32(addr, 6);
  const uint16_t part_a = (uint16_t)hash;
  const uint16_t part_b = (uint16_t)(hash >> 16);
  return part_a ^ part_b;
}

struct paxhashset {
  struct paxhashset *next;
  uint16_t elements[];
};

static struct paxhashset *pax_hashset_new(void) {
  struct paxhashset *phs =
      malloc(sizeof(struct paxhashset) + 32 * sizeof(uint32_t));
  if (!phs) return NULL;

  phs->next = NULL;
  memset(phs->elements, 0, 32 * sizeof(uint32_t));

  return phs;
}

static struct paxhashset *pax_hashset_add(struct paxhashset *phs,
                                          const uint8_t addr[6],
                                          bool *is_new_entry) {
  struct paxhashset *orig_phs = phs;
  struct paxhashset *last_phs = phs;
  uint32_t *first_empty = NULL;
  uint16_t hash = hash_mac_address(addr);
  const uint16_t orig_slot = hash & 31;
  uint16_t slot = orig_slot;

  *is_new_entry = false;

  while (phs) {
    if (phs->elements[slot] == hash) return orig_phs;

    if (!first_empty && phs->elements[slot] == 0)
      first_empty = &phs->elements[slot];

    slot++;
    if (slot == orig_slot) {
      last_phs = phs;
      phs = phs->next;
    }
  }

  if (first_empty) {
    *first_empty = hash;
    *is_new_entry = true;
    return orig_phs;
  }

  phs = pax_hashset_new();
  if (!phs) {
    // we ran out of memory, so replace the last element in this hashset
    // with the one we're trying to add.  if the replaced item ends up
    // being scanned again, it'll be added to the beginning of the link
    // chain, making this work similarly to a LRU cache.
    //
    // possible improvements:
    // - some kind of hysteresis
    // - limit the number of links in the chain to curb memory usage
    last_phs[orig_slot] = hash;
    return orig_phs;
  }

  phs->next = orig_phs;
  phs->elements[orig_slot] = hash;
  *is_new_entry = true;
  return phs;
}

static void pax_hashset_clear(struct paxhashset *phs) {
  if (phs) {
    pax_hashset_clear(phs->next);
    free(phs);
  }
}

static struct paxhashset *phs_wifi;
static struct paxhashset *phs_ble;
static int count_wifi, count_ble;

void libpax_counter_reset() {
  pax_hashset_clear(phs_wifi);
  pax_hashset_clear(phs_ble);
  count_wifi = count_ble = 0;

  phs_wifi = pax_hashset_new();
  phs_ble = pax_hashset_new();
}

int libpax_wifi_counter_count() { return count_wifi; }

int libpax_ble_counter_count() { return count_ble; }

IRAM_ATTR int mac_add(uint8_t *paddr, snifftype_t sniff_type) {
  if (!(paddr[0] & 0b10)) {
    // if it is NOT a locally administered ("random") mac, we don't count it
    return 0;
  }

  bool is_new_entry;
  switch (sniff_type) {
    case MAC_SNIFF_BLE:
      phs_ble = pax_hashset_add(phs_ble, paddr, &is_new_entry);
      if (is_new_entry) count_ble++;
      break;
    case MAC_SNIFF_WIFI:
      phs_wifi = pax_hashset_add(phs_wifi, paddr, &is_new_entry);
      if (is_new_entry) count_wifi++;
      break;
    default:
      return 0;
  }

  // function returns bool if a new and unique Wifi or BLE mac
  // was counted (true) or not (false)
  return is_new_entry;
}
