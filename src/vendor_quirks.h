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

#include <stdint.h>

enum vendor_quirk {
	/*
	 * The neighbor list in a BSS Transition Management request from an AP
	 * contains a very sparse BSS list which generally leads to poor roaming
	 * decisions.
	 */
	VENDOR_QUIRK_BAD_BSS_TM_CANDIDATE_LIST = 1 << 0,
	/*
	 * The PTK/GTK replay counter differs between a scan and FT
	 * authentication. This is not allowable in the spec, but seen with
	 * certain vendors.
	 */
	VENDOR_QUIRK_REPLAY_COUNTER_MISMATCH = 1 << 1,
};

uint32_t vendor_quirks(const uint8_t *oui);
