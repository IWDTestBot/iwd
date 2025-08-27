/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2025  Locus Robotics Corporation. All rights reserved.
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

#include <string.h>

#include <ell/ell.h>

#include "src/vendor_quirks.h"

static const struct {
	uint8_t oui[3];
	struct vendor_quirk quirks;
} oui_quirk_db[] = {
	{ }
};

void vendor_quirks_append_for_oui(const uint8_t *oui,
					struct vendor_quirk *quirks)
{
	size_t i;

	for (i = 0; i < L_ARRAY_SIZE(oui_quirk_db); i++) {
		const struct vendor_quirk *quirk = &oui_quirk_db[i].quirks;

		if (memcmp(oui_quirk_db[i].oui, oui, 3))
			continue;

		quirks->ignore_bss_tm_candidates |=
				quirk->ignore_bss_tm_candidates;
		quirks->replay_counter_mismatch |=
				quirk->replay_counter_mismatch;
	}
}

const char *vendor_quirks_to_string(struct vendor_quirk quirks)
{
	static char out[1024];
	size_t s = 0;

	if (!s)
		return NULL;

	return out;
}
