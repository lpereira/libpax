/*
LICENSE

Copyright  2020      Deutsche Bahn Station&Service AG

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
#include <string.h>
#include <stdlib.h>

#include "globals.h"
#include "libpax.h"

uint8_t channel = 0;  // channel rotation counter

static inline uint32_t fnv1a_32(const void *buffer, size_t len)
{
    const unsigned char *data = (unsigned char *)buffer;
    uint32_t hash;

    for (hash = 0x811c9dc5u; len--; data++) {
        hash = (hash ^ *data) * 0x1000193u;
    }

    return hash;
}

static uint32_t hash_mac_address(const uint8_t addr[6])
{
    return fnv1a_32(addr, 6);
}

struct paxhashmap {
    struct paxhashmap *next;
    uint8_t count;
    uint32_t elements[];
};

static struct paxhashmap *pax_hashmap_new(void)
{
    struct paxhashmap *phm = malloc(sizeof(struct paxhashmap) + 32 * sizeof(uint32_t));
    if (!phm)
        return NULL;

    phm->count = 0;
    phm->next = NULL;
    memset(phm->elements, 0, 32 * sizeof(uint32_t));

    return phm;
}

static uint32_t pax_hashmap_count(const struct paxhashmap *phm)
{
    return phm ? phm->count + pax_hashmap_count(phm->next) : 0;
}

static struct paxhashmap *pax_hashmap_add(struct paxhashmap *phm, const uint8_t addr[6], bool *is_new_entry)
{
    struct paxhashmap *orig_phm = phm;
    uint32_t *first_empty = NULL;
    uint8_t *first_empty_count = NULL;
    uint32_t hash = hash_mac_address(addr);
    const uint32_t orig_slot = hash & 31;
    uint32_t slot = orig_slot;

    *is_new_entry = false;

    while (phm) {
        if (phm->elements[slot] == hash)
            return orig_phm;

        if (!first_empty && phm->elements[slot] == 0) {
            first_empty = &phm->elements[slot];
            first_empty_count = &phm->count;
        }

        slot++;
        if (slot == orig_slot)
            phm = phm->next;
    }

    if (first_empty) {
        *first_empty = hash;
        *first_empty_count++;
        *is_new_entry = true;
        return orig_phm;
    }

    phm = pax_hashmap_new();
    if (phm) {
        phm->next = orig_phm;
        phm->elements[orig_slot] = hash;
        phm->count = 1;
        *is_new_entry = true;
    }

    return phm;
}

static void pax_hashmap_clear(struct paxhashmap *phm)
{
    if (phm) {
        pax_hashmap_clear(phm->next);
        free(phm);
    }
}

static struct paxhashmap *phm_wifi;
static struct paxhashmap *phm_ble;

void libpax_counter_reset() {
  pax_hashmap_clear(phm_wifi);
  pax_hashmap_clear(phm_ble);

  phm_wifi = pax_hashmap_new();
  phm_ble = pax_hashmap_new();
}

int libpax_wifi_counter_count() { return pax_hashmap_count(phm_wifi); }

int libpax_ble_counter_count() { return pax_hashmap_count(phm_ble); }

IRAM_ATTR int mac_add(uint8_t *paddr, snifftype_t sniff_type) {
  if (!(paddr[0] & 0b10)) {
      // if it is NOT a locally administered ("random") mac, we don't count it
      return 0;
  }

  bool is_new_entry;
  switch (sniff_type) {
  case MAC_SNIFF_BLE:
    phm_ble = pax_hashmap_add(phm_ble, paddr, &is_new_entry);
    break;
  case MAC_SNIFF_WIFI:
    phm_wifi = pax_hashmap_add(phm_wifi, paddr, &is_new_entry);
    break;
  default:
    return 0;
  }

  // function returns bool if a new and unique Wifi or BLE mac
  // was counted (true) or not (false)
  return is_new_entry;
}
