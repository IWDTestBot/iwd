/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2023  Intel Corporation. All rights reserved.
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

struct l_genl_msg;
struct l_dbus;

#define HWSIM_SERVICE "net.connman.hwsim"

enum hwsim_tx_control_flags {
	HWSIM_TX_CTL_REQ_TX_STATUS		= 1 << 0,
	HWSIM_TX_CTL_NO_ACK			= 1 << 1,
	HWSIM_TX_STAT_ACK			= 1 << 2,
};

struct radio_info_rec {
	int32_t id;
	uint32_t wiphy_id;
	char alpha2[2];
	bool p2p;
	bool custom_regdom;
	uint32_t regdom_idx;
	int channels;
	uint8_t addrs[2][ETH_ALEN];
	char *name;
	bool ap_only;
	struct l_dbus_message *pending;
	uint32_t cmd_id;
};

struct interface_info_rec {
	uint32_t id;
	struct radio_info_rec *radio_rec;
	uint8_t addr[ETH_ALEN];
	char *name;
	uint32_t iftype;
	int ref;
};

struct hwsim_tx_info {
	int8_t idx;
	uint8_t count;
};

struct hwsim_frame {
	int refcount;
	uint8_t src_ether_addr[ETH_ALEN];
	uint8_t dst_ether_addr[ETH_ALEN];
	struct radio_info_rec *src_radio;
	struct radio_info_rec *ack_radio;
	uint32_t flags;
	const uint64_t *cookie;
	int32_t signal;
	uint32_t frequency;
	uint16_t tx_info_len;
	const struct hwsim_tx_info *tx_info;
	uint16_t payload_len;
	const uint8_t *payload;
	bool acked;
	struct l_genl_msg *msg;
	int pending_callback_count;
};

typedef void (*hwsim_frame_cb_t)(struct hwsim_frame *frame, void *user_data);
typedef void (*hwsim_destroy_cb_t)(void *user_data);

unsigned int hwsim_watch_register(hwsim_frame_cb_t frame_cb, void *user_data,
			hwsim_destroy_cb_t destroy);

uint32_t hwsim_send_frame(struct hwsim_frame *frame,
				struct radio_info_rec *radio,
				l_genl_msg_func_t callback,
				void *user_data,
				l_genl_destroy_func_t destroy);
bool hwsim_send_tx_info(struct hwsim_frame *frame);

const struct l_queue_entry *hwsim_get_radios(void);
const struct l_queue_entry *hwsim_get_interfaces(void);

struct hwsim_frame *hwsim_frame_ref(struct hwsim_frame *frame);
void hwsim_frame_unref(struct hwsim_frame *frame);
