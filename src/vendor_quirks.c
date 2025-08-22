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
	uint32_t quirks;
} quirk_db[] = {
	/* Cisco Meraki */
	{ { 0x00, 0x18, 0x0a }, VENDOR_QUIRK_BAD_BSS_TM_CANDIDATE_LIST },
	/* Hewlitt Packard, owns Aruba */
	{ { 0x00, 0x0b, 0x86 }, VENDOR_QUIRK_REPLAY_COUNTER_MISMATCH },
};

uint32_t vendor_quirks(const uint8_t *oui)
{
	size_t i;
	uint32_t ret = 0;

	for (i = 0; i < L_ARRAY_SIZE(quirk_db); i++) {
		if (memcmp(quirk_db[i].oui, oui, 3))
			continue;

		ret |= quirk_db[i].quirks;
	}

	return ret;
}
