/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "src/blacklist.h"
#include "src/util.h"
#include "src/iwd.h"
#include "src/module.h"

/*
 * The current timeout is multiplied by this value after an entry is blacklisted
 * more than once.
 */
#define BLACKLIST_DEFAULT_MULTIPLIER	30

/* Initial timeout for a new blacklist entry */
#define BLACKLIST_DEFAULT_TIMEOUT	60

/* The maximum amount of time a BSS can be blacklisted for */
#define BLACKLIST_DEFAULT_MAX_TIMEOUT	86400

static uint64_t blacklist_multiplier;
static uint64_t blacklist_initial_timeout;
static uint64_t blacklist_max_timeout;

struct blacklist_entry {
	uint8_t addr[6];
	uint64_t added_time;
	uint64_t expire_time;
	enum blacklist_reason reason;
};

struct blacklist_search {
	const uint8_t *addr;
	enum blacklist_reason reason;
};

static struct l_queue *blacklist;

static struct blacklist_entry *blacklist_entry_new(const uint8_t *addr,
						enum blacklist_reason reason)
{
	struct blacklist_entry *entry;
	uint64_t added;
	uint64_t expires;

	switch (reason) {
	case BLACKLIST_REASON_CONNECT_FAILED:
		if (!blacklist_initial_timeout)
			return NULL;

		added = l_time_now();
		expires = l_time_offset(added, blacklist_initial_timeout);
		break;
	case BLACKLIST_REASON_TRANSIENT_ERROR:
		/*
		 * The temporary blacklist is a special case where entries are
		 * required to be removed manually. This type of blacklist is
		 * only used for an ongoing connection attempt to iterate BSS's
		 * and not retry until all have been exhausted.
		 */
		added = 0;
		expires = 0;
		break;
	default:
		l_warn("Unhandled blacklist reason: %u", reason);
		return NULL;
	}

	entry = l_new(struct blacklist_entry, 1);

	entry->added_time = added;
	entry->expire_time = expires;
	entry->reason = reason;
	memcpy(entry->addr, addr, 6);

	return entry;
}

static bool check_if_expired(void *data, void *user_data)
{
	struct blacklist_entry *entry = data;
	uint64_t now = l_get_u64(user_data);

	if (entry->reason == BLACKLIST_REASON_TRANSIENT_ERROR)
		return false;

	if (l_time_after(now, entry->expire_time)) {
		l_debug("Removing entry "MAC" on prune", MAC_STR(entry->addr));
		l_free(entry);
		return true;
	}

	return false;
}

static void blacklist_prune(void)
{
	uint64_t now = l_time_now();

	l_queue_foreach_remove(blacklist, check_if_expired, &now);
}

static bool match_addr(const void *a, const void *b)
{
	const struct blacklist_entry *entry = a;
	const struct blacklist_search *search = b;

	if (entry->reason != search->reason)
		return false;

	if (!memcmp(entry->addr, search->addr, 6))
		return true;

	return false;
}

void blacklist_add_bss(const uint8_t *addr, enum blacklist_reason reason)
{
	struct blacklist_entry *entry;
	struct blacklist_search search = {
		.addr = addr,
		.reason = reason
	};

	blacklist_prune();

	entry = l_queue_find(blacklist, match_addr, &search);

	if (entry) {
		uint64_t offset = l_time_diff(entry->added_time,
							entry->expire_time);

		offset *= blacklist_multiplier;

		if (offset > blacklist_max_timeout)
			offset = blacklist_max_timeout;

		entry->expire_time = l_time_offset(entry->added_time, offset);

		return;
	}

	entry = blacklist_entry_new(addr, reason);
	if (entry)
		l_queue_push_tail(blacklist, entry);
}

bool blacklist_contains_bss(const uint8_t *addr, enum blacklist_reason reason)
{
	struct blacklist_search search = {
		.addr = addr,
		.reason = reason
	};

	blacklist_prune();

	return l_queue_find(blacklist, match_addr, &search) != NULL;
}

void blacklist_remove_bss(const uint8_t *addr, enum blacklist_reason reason)
{
	struct blacklist_entry *entry;
	struct blacklist_search search = {
		.addr = addr,
		.reason = reason
	};

	blacklist_prune();

	entry = l_queue_remove_if(blacklist, match_addr, &search);

	if (!entry)
		return;

	l_free(entry);
}

static int blacklist_init(void)
{
	const struct l_settings *config = iwd_get_config();

	if (!l_settings_get_uint64(config, "Blacklist", "InitialTimeout",
					&blacklist_initial_timeout))
		blacklist_initial_timeout = BLACKLIST_DEFAULT_TIMEOUT;

	/* For easier user configuration the timeout values are in seconds */
	blacklist_initial_timeout *= L_USEC_PER_SEC;

	if (!l_settings_get_uint64(config, "Blacklist",
					"Multiplier",
					&blacklist_multiplier))
		blacklist_multiplier = BLACKLIST_DEFAULT_MULTIPLIER;

	if (blacklist_multiplier == 0) {
		l_warn("[Blacklist].Multiplier cannot be zero, setting to 1");
		blacklist_multiplier = 1;
	}

	if (!l_settings_get_uint64(config, "Blacklist",
					"MaximumTimeout",
					&blacklist_max_timeout))
		blacklist_max_timeout = BLACKLIST_DEFAULT_MAX_TIMEOUT;

	blacklist_max_timeout *= L_USEC_PER_SEC;

	if (blacklist_initial_timeout > blacklist_max_timeout)
		l_warn("[Blacklist].InitialTimeout exceeded "
			"[Blacklist].MaximumTimeout!");

	if (!blacklist_initial_timeout)
		l_debug("initial timeout was zero, blacklist will be disabled");

	blacklist = l_queue_new();

	return 0;
}

static void blacklist_exit(void)
{
	l_queue_destroy(blacklist, l_free);
}

IWD_MODULE(blacklist, blacklist_init, blacklist_exit)
