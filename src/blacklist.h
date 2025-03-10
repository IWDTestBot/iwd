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

enum blacklist_reason {
	/*
	 * When a BSS is blacklisted using this reason IWD will refuse to
	 * connect to it via autoconnect
	 */
	BLACKLIST_REASON_PERMANENT,
	/*
	 * When a BSS is blacklisted due to a specific subset of error codes.
	 * This reason is somewhat of a special case and has no expiration. It
	 * is assumed that the calling module will remove these entries when
	 * appropriate (after a connection/disconnection)
	 */
	BLACKLIST_REASON_TEMPORARY,
};

void blacklist_add_bss(const uint8_t *addr, enum blacklist_reason reason);
bool blacklist_contains_bss(const uint8_t *addr, enum blacklist_reason reason);
void blacklist_remove_bss(const uint8_t *addr, enum blacklist_reason reason);
