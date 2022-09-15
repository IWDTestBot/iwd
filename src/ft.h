/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

struct handshake_state;
struct scan_bss;

typedef int (*ft_tx_action_func_t)(uint32_t ifindex, const uint8_t *dest,
					struct iovec *iov, size_t iov_len);

typedef int (*ft_tx_associate_func_t)(uint32_t ifindex,
					const uint8_t *prev_bssid,
					struct iovec *ie_iov, size_t iov_len);

typedef void (*ft_authenticate_cb_t)(int err, const uint8_t *addr,
					uint32_t freq, void *user_data);

void __ft_set_tx_action_func(ft_tx_action_func_t func);
void __ft_set_tx_associate_func(ft_tx_associate_func_t func);
int __ft_rx_associate(uint32_t ifindex, const uint8_t *frame,
			size_t frame_len);

struct ft_sm *ft_sm_new(struct handshake_state *hs);
void ft_sm_free(struct ft_sm *sm);

bool ft_sm_can_associate(struct ft_sm *sm, const struct scan_bss *target);

int ft_action(struct ft_sm *sm, const struct scan_bss *target);
int ft_associate(struct ft_sm *sm, const uint8_t *addr);
int ft_authenticate(struct ft_sm *sm, const struct scan_bss *target,
			ft_authenticate_cb_t cb, void *user_data);
