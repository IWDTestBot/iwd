/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2023  Cruise LLC. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>

#include <ell/ell.h>
#include "ell/useful.h"

#include "src/module.h"
#include "src/pmksa.h"

static uint64_t dot11RSNAConfigPMKLifetime = 43200ULL * L_USEC_PER_SEC;
static uint32_t pmksa_cache_capacity = 255;

struct min_heap {
	struct pmksa **data;
	uint32_t capacity;
	uint32_t used;
};

static struct min_heap cache;

static __always_inline void swap_ptr(void *l, void *r)
{
	struct pmksa **lp = l;
	struct pmksa **rp = r;

	SWAP(*lp, *rp);
}

static __always_inline
bool pmksa_compare_expiration(const void *l, const void *r)
{
	const struct pmksa * const *lp = l;
	const struct pmksa * const *rp = r;

	return (*lp)->expiration < (*rp)->expiration;
}

static struct l_minheap_ops ops = {
	.elem_size = sizeof(struct pmksa *),
	.swap = swap_ptr,
	.less = pmksa_compare_expiration,
};

static int pmksa_cache_find(const uint8_t spa[static 6],
					const uint8_t aa[static 6],
					const uint8_t *ssid, size_t ssid_len,
					uint32_t akm)
{
	unsigned int i;

	for (i = 0; i < cache.used; i++) {
		struct pmksa *pmksa = cache.data[i];

		if (memcmp(pmksa->spa, spa, sizeof(pmksa->spa)))
			continue;

		if (memcmp(pmksa->aa, aa, sizeof(pmksa->aa)))
			continue;

		if (ssid_len != pmksa->ssid_len)
			continue;

		if (memcmp(pmksa->ssid, ssid, ssid_len))
			continue;

		if (akm & pmksa->akm)
			return i;
	}

	return -ENOENT;
}

/*
 * Try to obtain a PMKSA entry from the cache.  If the the entry matching
 * the parameters is found, it is removed from the cache and returned to the
 * caller.  The caller is responsible for managing the returned pmksa
 * structure
 */
struct pmksa *pmksa_cache_get(const uint8_t spa[static 6],
				const uint8_t aa[static 6],
				const uint8_t *ssid, size_t ssid_len,
				uint32_t akm)
{
	int r = pmksa_cache_find(spa, aa, ssid, ssid_len, akm);

	if (r < 0)
		return NULL;

	cache.used -= 1;
	if ((uint32_t) r == cache.used)
		goto done;

	SWAP(cache.data[r], cache.data[cache.used]);
	__minheap_sift_down(cache.data, cache.used, r, &ops);

done:
	return cache.data[cache.used];
}

/*
 * Put a PMKSA into the cache.  It will be sorted in soonest-to-expire order.
 * If the cache is full, then soonest-to-expire entry is removed first.
 */
int pmksa_cache_put(struct pmksa *pmksa)
{
	if (cache.used == cache.capacity) {
		l_free(cache.data[0]);
		cache.data[0] = pmksa;
		__minheap_sift_down(cache.data, cache.used, 0, &ops);
		return 0;
	}

	cache.data[cache.used] = pmksa;
	__minheap_sift_up(cache.data, cache.used, &ops);
	cache.used += 1;

	return 0;
}

/*
 * Expire all PMKSA entries with expiration time smaller or equal to the cutoff
 * time.
 */
int pmksa_cache_expire(uint64_t cutoff)
{
	int i;
	int used = cache.used;
	int remaining = 0;

	for (i = 0; i < used; i++) {
		if (cache.data[i]->expiration <= cutoff) {
			l_free(cache.data[i]);
			continue;
		}

		cache.data[remaining] = cache.data[i];
		remaining += 1;
	}

	cache.used = remaining;

	for (i = cache.used >> 1; i >= 0; i--)
		__minheap_sift_down(cache.data, cache.used, i, &ops);

	return used - remaining;
}

/*
 * Flush all PMKSA entries from the cache, regardless of expiration time.
 */
int pmksa_cache_flush(void)
{
	uint32_t i;

	for (i = 0; i < cache.used; i++)
		l_free(cache.data[i]);

	memset(cache.data, 0, cache.capacity * sizeof(struct pmksa *));
	cache.used = 0;
	return 0;
}

struct pmksa **__pmksa_cache_get_all(uint32_t *out_n_entries)
{
	if (out_n_entries)
		*out_n_entries = cache.used;

	return cache.data;
}

uint64_t pmksa_lifetime(void)
{
	return dot11RSNAConfigPMKLifetime;
}

void __pmksa_set_config(const struct l_settings *config)
{
	l_settings_get_uint(config, "PMKSA", "Capacity",
					&pmksa_cache_capacity);
}

static int pmksa_init(void)
{
	cache.capacity = pmksa_cache_capacity;
	cache.used = 0;
	cache.data = l_new(struct pmksa *, cache.capacity);

	return 0;
}

static void pmksa_exit(void)
{
	pmksa_cache_flush();
	l_free(cache.data);
}

IWD_MODULE(pmksa, pmksa_init, pmksa_exit);
