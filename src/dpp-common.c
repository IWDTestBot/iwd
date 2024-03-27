/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/missing.h"
#include "src/dbus.h"
#include "src/netdev.h"
#include "src/module.h"
#include "src/dpp-util.h"
#include "src/band.h"
#include "src/frame-xchg.h"
#include "src/offchannel.h"
#include "src/wiphy.h"
#include "src/ie.h"
#include "src/iwd.h"
#include "src/util.h"
#include "src/crypto.h"
#include "src/mpdu.h"
#include "ell/useful.h"
#include "src/common.h"
#include "src/json.h"
#include "src/storage.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/network.h"
#include "src/handshake.h"
#include "src/nl80211util.h"
#include "src/knownnetworks.h"
#include "src/dpp-common.h"

#define DPP_HDR_LEN			6
#define DPP_ACTION_VENDOR_SPECIFIC	0x09
#define DPP_ACTION_GAS_REQUEST		0x0a
#define DPP_ACTION_GAS_RESPONSE		0x0b
#define DPP_AUTH_PROTO_TIMEOUT		10
#define DPP_PKEX_PROTO_TIMEOUT		120

struct dpp_sm {
	char *uri;
	uint8_t role;

	uint8_t *own_asn1;
	size_t own_asn1_len;
	uint8_t *peer_asn1;
	size_t peer_asn1_len;
	uint8_t own_boot_hash[32];
	uint8_t peer_boot_hash[32];
	uint8_t own_chirp_hash[32];
	const struct l_ecc_curve *curve;
	size_t key_len;
	size_t nonce_len;
	struct l_ecc_scalar *boot_private;
	struct l_ecc_point *boot_public;
	struct l_ecc_point *peer_boot_public;

	enum dpp_state state;

	uint8_t r_nonce[32];
	uint8_t i_nonce[32];
	uint8_t e_nonce[32];

	struct l_ecc_scalar *m;
	uint64_t ke[L_ECC_MAX_DIGITS];
	uint64_t k1[L_ECC_MAX_DIGITS];
	uint64_t k2[L_ECC_MAX_DIGITS];
	uint64_t auth_tag[L_ECC_MAX_DIGITS];

	struct l_ecc_scalar *proto_private;
	struct l_ecc_point *own_proto_public;

	struct l_ecc_point *peer_proto_public;

	uint8_t diag_token;

	/* Timeout of auth/config/PKEX protocols */
	uint64_t proto_timeout;
	struct l_timeout *timeout;

	struct dpp_configuration *config;

	/* PKEX-specific values */
	char *pkex_id;
	char *pkex_key;
	uint8_t pkex_version;
	struct l_ecc_point *peer_encr_key;
	struct l_ecc_point *pkex_m;
	/* Ephemeral key Y' or X' for enrollee or configurator */
	struct l_ecc_point *y_or_x;
	/* Ephemeral key pair y/Y or x/X */
	struct l_ecc_point *pkex_public;
	struct l_ecc_scalar *pkex_private;
	uint8_t z[L_ECC_SCALAR_MAX_BYTES];
	size_t z_len;
	uint8_t u[L_ECC_SCALAR_MAX_BYTES];
	size_t u_len;
	uint8_t pkex_own_mac[6];
	uint8_t pkex_peer_mac[6];
	/* Set to either own/peer mac depending on configuration */
	const uint8_t *mac_initiator;
	const uint8_t *mac_responder;

	/*
	 * Since the authenticate frame may request a channel switch we do need
	 * to expose this detail within the common code.
	 */
	uint8_t channel[2];

	uint8_t *frame_pending;
	size_t frame_len;
	dpp_write_cb_t write;
	dpp_event_cb_t event_cb;
	void *user_data;

	bool skip_presence : 1;
	bool mutual_auth : 1;
	bool initiator : 1;
};

static void dpp_failed(struct dpp_sm *dpp)
{
	if (dpp->event_cb)
		dpp->event_cb(DPP_EVENT_FAILED, NULL, dpp->user_data);
}

static void dpp_protocol_timeout(struct l_timeout *timeout, void *user_data)
{
	struct dpp_sm *dpp = user_data;

	l_debug("DPP timed out");

	dpp_failed(dpp);
}

static void dpp_reset_protocol_timer(struct dpp_sm *dpp, uint64_t time)
{
	if (dpp->timeout)
		l_timeout_modify(dpp->timeout, time);
	else
		dpp->timeout = l_timeout_create(time, dpp_protocol_timeout,
						dpp, NULL);
}

struct dpp_sm *dpp_sm_new(dpp_event_cb_t event,
				const struct l_ecc_point *boot_public,
				const struct l_ecc_scalar *boot_private,
				void *user_data)
{
	struct dpp_sm *dpp = l_new(struct dpp_sm, 1);

	dpp->state = DPP_STATE_NOTHING;
	dpp->curve = l_ecc_point_get_curve(boot_public);
	dpp->key_len = l_ecc_curve_get_scalar_bytes(dpp->curve);
	dpp->nonce_len = dpp_nonce_len_from_key_len(dpp->key_len);
	dpp->boot_public = l_ecc_point_clone(boot_public);
	dpp->boot_private = l_ecc_scalar_clone(boot_private);
	dpp->own_asn1 = dpp_point_to_asn1(dpp->boot_public, &dpp->own_asn1_len);
	dpp->event_cb = event;
	dpp->user_data = user_data;

	dpp_hash(L_CHECKSUM_SHA256, dpp->own_boot_hash, 1, dpp->own_asn1,
			dpp->own_asn1_len);
	dpp_hash(L_CHECKSUM_SHA256, dpp->own_chirp_hash, 2, "chirp",
			strlen("chirp"), dpp->own_asn1, dpp->own_asn1_len);

	return dpp;
}

void dpp_sm_set_write_handler(struct dpp_sm *dpp, dpp_write_cb_t write)
{
	dpp->write = write;

	if (!dpp->write)
		return;

	/* Handle writing frame */
}

static void dpp_free_auth_data(struct dpp_sm *dpp)
{
	if (dpp->own_proto_public) {
		l_ecc_point_free(dpp->own_proto_public);
		dpp->own_proto_public = NULL;
	}

	if (dpp->proto_private) {
		l_ecc_scalar_free(dpp->proto_private);
		dpp->proto_private = NULL;
	}

	if (dpp->peer_proto_public) {
		l_ecc_point_free(dpp->peer_proto_public);
		dpp->peer_proto_public = NULL;
	}

	if (dpp->peer_boot_public) {
		l_ecc_point_free(dpp->peer_boot_public);
		dpp->peer_boot_public = NULL;
	}

	if (dpp->m) {
		l_ecc_scalar_free(dpp->m);
		dpp->m = NULL;
	}

	if (dpp->pkex_m) {
		l_ecc_point_free(dpp->pkex_m);
		dpp->pkex_m = NULL;
	}

	if (dpp->y_or_x) {
		l_ecc_point_free(dpp->y_or_x);
		dpp->y_or_x = NULL;
	}

	if (dpp->pkex_public) {
		l_ecc_point_free(dpp->pkex_public);
		dpp->pkex_public = NULL;
	}

	if (dpp->pkex_private) {
		l_ecc_scalar_free(dpp->pkex_private);
		dpp->pkex_private = NULL;
	}
}

static void dpp_free_pending_pkex_data(struct dpp_sm *dpp)
{
	if (dpp->pkex_id) {
		l_free(dpp->pkex_id);
		dpp->pkex_id = NULL;
	}

	if (dpp->pkex_key) {
		l_free(dpp->pkex_key);
		dpp->pkex_key = NULL;
	}

	if (dpp->peer_encr_key) {
		l_ecc_point_free(dpp->peer_encr_key);
		dpp->peer_encr_key = NULL;
	}
}

void dpp_sm_free(struct dpp_sm *dpp)
{
	if (dpp->boot_public) {
		l_ecc_point_free(dpp->boot_public);
		dpp->boot_public = NULL;
	}

	if (dpp->boot_private) {
		l_ecc_scalar_free(dpp->boot_private);
		dpp->boot_private = NULL;
	}

	if (dpp->timeout) {
		l_timeout_remove(dpp->timeout);
		dpp->timeout = NULL;
	}

	if (dpp->config) {
		dpp_configuration_free(dpp->config);
		dpp->config = NULL;
	}

	if (dpp->peer_asn1) {
		l_free(dpp->peer_asn1);
		dpp->peer_asn1 = NULL;
	}

	if (dpp->own_asn1) {
		l_free(dpp->own_asn1);
		dpp->own_asn1 = NULL;
	}

	if (dpp->frame_pending) {
		l_free(dpp->frame_pending);
		dpp->frame_pending = NULL;
	}

	dpp->state = DPP_STATE_NOTHING;
	dpp->pkex_version = 0;

	explicit_bzero(dpp->r_nonce, dpp->nonce_len);
	explicit_bzero(dpp->i_nonce, dpp->nonce_len);
	explicit_bzero(dpp->e_nonce, dpp->nonce_len);
	explicit_bzero(dpp->ke, dpp->key_len);
	explicit_bzero(dpp->k1, dpp->key_len);
	explicit_bzero(dpp->k2, dpp->key_len);
	explicit_bzero(dpp->auth_tag, dpp->key_len);
	explicit_bzero(dpp->z, dpp->key_len);
	explicit_bzero(dpp->u, dpp->u_len);

	dpp_free_pending_pkex_data(dpp);

	dpp_free_auth_data(dpp);

	l_free(dpp);
}

static bool dpp_start_authentication(struct dpp_sm *dpp)
{
	l_ecdh_generate_key_pair(dpp->curve, &dpp->proto_private,
					&dpp->own_proto_public);

	l_getrandom(dpp->i_nonce, dpp->nonce_len);

	dpp->m = dpp_derive_k1(dpp->peer_boot_public,
					dpp->proto_private, dpp->k1);

	dpp->state = DPP_STATE_AUTHENTICATING;

	return true;
}

void dpp_sm_set_peer_bootstrap(struct dpp_sm *dpp,
					struct l_ecc_point *public)
{
	dpp->peer_boot_public = l_ecc_point_clone(public);
	dpp->peer_asn1 = dpp_point_to_asn1(public, &dpp->peer_asn1_len);

	dpp_hash(L_CHECKSUM_SHA256, dpp->peer_boot_hash, 1, dpp->peer_asn1,
			dpp->peer_asn1_len);
}

const uint8_t *dpp_sm_get_own_asn1(struct dpp_sm *dpp, size_t *len)
{
	*len = dpp->own_asn1_len;

	return dpp->own_asn1;
}

void dpp_sm_set_configuration(struct dpp_sm *dpp,
					struct dpp_configuration *config)
{
	dpp->config = config;
}

const struct dpp_configuration *dpp_sm_get_configuration(struct dpp_sm *dpp)
{
	return dpp->config;
}

void dpp_sm_set_role(struct dpp_sm *dpp, enum dpp_capability role)
{
	dpp->role = role;
}

void dpp_sm_set_skip_presence(struct dpp_sm *dpp, bool skip)
{
	dpp->skip_presence = skip;
}

void dpp_sm_set_channel(struct dpp_sm *dpp, uint8_t oper_class, uint8_t channel)
{
	dpp->channel[0] = oper_class;
	dpp->channel[1] = channel;
}

enum dpp_state dpp_sm_get_state(struct dpp_sm *dpp)
{
	return dpp->state;
}

bool dpp_sm_start_initiator(struct dpp_sm *dpp)
{
	if (L_WARN_ON(!dpp->peer_boot_public))
		return false;

	dpp->initiator = true;

	if (dpp->skip_presence) {
		dpp_start_authentication(dpp);
		dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);
	} else
		dpp->state = DPP_STATE_PRESENCE;

	return true;
}

bool dpp_sm_start_responder(struct dpp_sm *dpp)
{
	l_ecdh_generate_key_pair(dpp->curve, &dpp->proto_private,
					&dpp->own_proto_public);
	dpp->initiator = false;

	dpp->state = DPP_STATE_PRESENCE;

	return true;
}

void dpp_sm_set_pkex_identifier(struct dpp_sm *dpp, const char *identifier)
{
	dpp->pkex_id = l_strdup(identifier);
}

void dpp_sm_set_pkex_key(struct dpp_sm *dpp, const char *key)
{
	dpp->pkex_key = l_strdup(key);
}

void dpp_sm_set_pkex_own_mac(struct dpp_sm *dpp, const uint8_t *mac)
{
	memcpy(dpp->pkex_own_mac, mac, 6);
}

void dpp_sm_set_pkex_peer_mac(struct dpp_sm *dpp, const uint8_t *mac)
{
	memcpy(dpp->pkex_peer_mac, mac, 6);

	if (dpp->initiator) {
		dpp->mac_responder = dpp->pkex_peer_mac;
		dpp->mac_initiator = dpp->pkex_own_mac;
	} else {
		dpp->mac_initiator = dpp->pkex_peer_mac;
		dpp->mac_responder = dpp->pkex_own_mac;
	}
}

bool dpp_sm_pkex_start_initiator(struct dpp_sm *dpp)
{
	_auto_(l_ecc_point_free) struct l_ecc_point *qi = NULL;

	if (!dpp->pkex_key)
		return false;

	/*
	 * "DPP R2 devices are expected to use PKEXv1 by default"
	 *
	 * TODO: Support setting version (v2 required for TCP encapsulation)
	 */
	dpp->pkex_version = 1;

	if (!l_ecdh_generate_key_pair(dpp->curve, &dpp->pkex_private,
					&dpp->pkex_public))
		return false;

	/*
	 * "If Qi is the point-at-infinity, the code shall be deleted and the
	 * user should be notified to provision a new code"
	 */
	qi = dpp_derive_qi(dpp->curve, dpp->pkex_key, dpp->pkex_id,
				dpp->pkex_own_mac);
	if (!qi || l_ecc_point_is_infinity(qi)) {
		l_debug("Cannot derive Qi, provision a new code");
		goto failed;
	}

	dpp->pkex_m = l_ecc_point_new(dpp->curve);

	if (!l_ecc_point_add(dpp->pkex_m, dpp->pkex_public, qi))
		goto failed;

	dpp->initiator = true;

	dpp->mac_initiator = dpp->pkex_own_mac;
	/* Won't know until we receive a response */
	dpp->mac_responder = NULL;

	dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);

	/* Send exchange request */

	return true;

failed:
	return false;
}

bool dpp_sm_pkex_start_responder(struct dpp_sm *dpp)
{
	dpp->initiator = false;

	dpp->mac_responder = dpp->pkex_own_mac;
	/* Won't know until we receive the first frame */
	dpp->mac_initiator = NULL;

	dpp->state = DPP_STATE_PKEX_EXCHANGE;
	dpp->pkex_version = 1;

	dpp_reset_protocol_timer(dpp, DPP_PKEX_PROTO_TIMEOUT);

	return true;
}

void dpp_handle_rx(struct dpp_sm *dpp, const uint8_t *data, size_t len)
{
	/* Handle frame */
}
