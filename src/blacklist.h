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
	BLACKLIST_REASON_CONNECT_FAILED,
	/*
	 * Used to blacklist a BSS under certain failure conditions that don't
	 * warrant a full ban from connecting. This can include an invalid
	 * password, or an auth/assoc failure with a subset of status codes that
	 * indicate the BSS is overloaded or cannot accept new connections.
	 *
	 * This is used to mark the last BSS as having failed, and to continue
	 * iterating BSS's. Once the list has been exhausted or a connection has
	 * succeeded all blacklist entries with this reason code should be
	 * cleared.
	 */
	BLACKLIST_REASON_TRANSIENT_ERROR,
	/*
	 * This type of blacklist is added when a BSS requests IWD roams
	 * elsewhere. This is to aid in preventing IWD from roaming/connecting
	 * back to that BSS in the future unless there are no other "good"
	 * candidates to connect to.
	 */
	BLACKLIST_REASON_ROAM_REQUESTED,
};

void blacklist_add_bss(const uint8_t *addr, enum blacklist_reason reason);
bool blacklist_contains_bss(const uint8_t *addr, enum blacklist_reason reason);
void blacklist_remove_bss(const uint8_t *addr, enum blacklist_reason reason);
