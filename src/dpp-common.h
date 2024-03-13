/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2024  Locus Robotics
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

struct dpp_sm;
struct l_ecc_point;
struct l_ecc_scalar;

enum dpp_state {
	DPP_STATE_NOTHING,
	DPP_STATE_PRESENCE,
	DPP_STATE_PKEX_EXCHANGE,
	DPP_STATE_PKEX_COMMIT_REVEAL,
	DPP_STATE_AUTHENTICATING,
	DPP_STATE_CONFIGURING,
};

enum dpp_capability {
	DPP_CAPABILITY_ENROLLEE = 0x01,
	DPP_CAPABILITY_CONFIGURATOR = 0x02,
};

enum dpp_event {
	/*
	 * PEER_ACCEPTED indicates an initial DPP frame has been received and
	 * accepted. This could be either a PKEX or an auth frame when DPP is
	 * running as either a configurator or enrollee. This should be
	 * used by the encapsulating protocol to note the peer address (MAC
	 * or IP) and from then on only accept frames from this peer until DPP
	 * has completed.
	 */
	DPP_EVENT_PEER_ACCEPTED,
	/*
	 * The authenticate request frame included a channel attribute. The
	 * encapsulating protocol must switch to this channel to continue the
	 * protocol (only applicable to 802.11 encapsulation). Event data is
	 * two bytes: [oper_class, channel]
	 */
	DPP_EVENT_CHANNEL_SWITCH,
	/*
	 * A key corresponding to an identifier (set in event_data) is now
	 * required. The encapsulating protocol must retrieve the key and
	 * notify using dpp_sm_set_pkex_key().
	 */
	DPP_EVENT_PKEX_KEY_REQUESTED,
	DPP_EVENT_SUCCESS,
	DPP_EVENT_FAILED,
};

typedef void (*dpp_event_cb_t)(enum dpp_event event, const void *event_data,
				void *user_data);

typedef void (*dpp_write_cb_t)(const uint8_t *data, size_t len,
				void *user_data);

struct dpp_sm *dpp_sm_new(dpp_event_cb_t event,
				const struct l_ecc_point *boot_public,
				const struct l_ecc_scalar *boot_private,
				void *user_data);

void dpp_sm_free(struct dpp_sm *dpp);

void dpp_handle_rx(struct dpp_sm *dpp, const uint8_t *data, size_t len);
void dpp_sm_set_write_handler(struct dpp_sm *dpp, dpp_write_cb_t write);

void dpp_sm_set_peer_bootstrap(struct dpp_sm *dpp,
					struct l_ecc_point *public);
void dpp_sm_set_own_bootstrap(struct dpp_sm *dpp, struct l_ecc_point *public,
					struct l_ecc_scalar *private);
const uint8_t *dpp_sm_get_own_asn1(struct dpp_sm *dpp, size_t *len);

void dpp_sm_set_configuration(struct dpp_sm *dpp,
					struct dpp_configuration *config);
const struct dpp_configuration *dpp_sm_get_configuration(struct dpp_sm *dpp);

void dpp_sm_set_skip_presence(struct dpp_sm *dpp, bool skip);

void dpp_sm_set_channel(struct dpp_sm *dpp, uint8_t oper_class,
			uint8_t channel);
enum dpp_state dpp_sm_get_state(struct dpp_sm *dpp);

bool dpp_sm_start_initiator(struct dpp_sm *dpp);
bool dpp_sm_start_responder(struct dpp_sm *dpp);

void dpp_sm_set_pkex_identifier(struct dpp_sm *dpp, const char *identifier);
void dpp_sm_set_pkex_key(struct dpp_sm *dpp, const char *key);
void dpp_sm_set_pkex_own_mac(struct dpp_sm *dpp, const uint8_t *mac);
void dpp_sm_set_pkex_peer_mac(struct dpp_sm *dpp, const uint8_t *mac);

bool dpp_sm_pkex_start_initiator(struct dpp_sm *dpp);
bool dpp_sm_pkex_start_responder(struct dpp_sm *dpp);
