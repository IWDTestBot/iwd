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

/*
 * Builds only the core DPP header. This is shared between DPP over 80211 and
 * over TCP. Those protocols are required to encapsulate the core message as
 * required by the spec.
 */
static size_t dpp_build_header(enum dpp_frame_type type, uint8_t *buf)
{
	uint8_t *ptr = buf;

	*ptr++ = DPP_ACTION_VENDOR_SPECIFIC;
	memcpy(ptr, wifi_alliance_oui, 3);
	ptr += 3;
	*ptr++ = 0x1a;			/* WiFi Alliance DPP OI type */
	*ptr++ = 1;			/* Cryptosuite */
	*ptr++ = type;

	return ptr - buf;
}

/*
 * For some reason the DPP spec decided to use GAS frame formats only for the
 * configuration request and response. There is no explicit DPP frame type for
 * these messages, hence the boolean 'request' parameter. The header will be
 * formatted either for a configuration request or configuration response.
 *
 * See Section 8.3 DPP Generic Advertisement Service (GAS) frames
 *
 * As with the more generic header above, the specific protocol handlers will
 * be required to add extra header information (80211 or TCP).
 */
static size_t dpp_build_config_header(bool request, uint8_t diag_token,
					uint8_t *buf)
{
	uint8_t *ptr = buf;

	*ptr++ = request ? DPP_ACTION_GAS_REQUEST: DPP_ACTION_GAS_RESPONSE;
	*ptr++ = diag_token;

	if (!request) {
		/* Status */
		l_put_le16(0, ptr);
		ptr += 2;
		/* Not fragmented */
		l_put_le16(0, ptr);
		ptr += 2;
	}

	*ptr++ = IE_TYPE_ADVERTISEMENT_PROTOCOL;
	*ptr++ = 8; /* len */
	if (request)
		*ptr++ = 0x7f;
	else
		*ptr++ = 0x00;

	*ptr++ = IE_TYPE_VENDOR_SPECIFIC;
	*ptr++ = 5;
	memcpy(ptr, wifi_alliance_oui, 3);
	ptr += 3;
	*ptr++ = 0x1a;
	*ptr++ = 1;

	return ptr - buf;
}

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

static bool dpp_check_roles(struct dpp_sm *dpp, uint8_t peer_capa)
{
	if (dpp->role == DPP_CAPABILITY_ENROLLEE &&
			!(peer_capa & DPP_CAPABILITY_CONFIGURATOR))
		return false;
	else if (dpp->role == DPP_CAPABILITY_CONFIGURATOR &&
			!(peer_capa & DPP_CAPABILITY_ENROLLEE))
		return false;

	return true;
}

static void dpp_try_write(struct dpp_sm *dpp, const uint8_t *frame,
				size_t frame_len)
{
	if (!dpp->write) {
		if (dpp->frame_pending) {
			l_free(dpp->frame_pending);
			dpp->frame_pending = NULL;
		}

		l_debug("No write handler, waiting to send");
		dpp->frame_pending = l_memdup(frame, frame_len);
		dpp->frame_len = frame_len;
		return;
	}

	dpp->write(frame, frame_len, dpp->user_data);
}

static void dpp_send_presence(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 64];
	uint8_t *ptr = frame;

	ptr += dpp_build_header(DPP_FRAME_PRESENCE_ANNOUNCEMENT, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->own_chirp_hash,
				sizeof(dpp->own_chirp_hash));

	dpp->state = DPP_STATE_PRESENCE;

	l_debug("sending presence announcement");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_auth_request(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint8_t version = 2;

	ptr += dpp_build_header(DPP_FRAME_AUTHENTICATION_REQUEST, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->peer_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);
	ptr += dpp_append_point(ptr, DPP_ATTR_INITIATOR_PROTOCOL_KEY,
				dpp->own_proto_public);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	if (dpp->role == DPP_CAPABILITY_CONFIGURATOR && dpp->channel[0])
		ptr += dpp_append_attr(ptr, DPP_ATTR_CHANNEL, dpp->channel, 2);

	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->k1, dpp->key_len, 2,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_INITIATOR_CAPABILITIES,
			(size_t) 1, &dpp->role);

	dpp->state = DPP_STATE_AUTHENTICATING;

	l_debug("sending auth request");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_auth_response(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 512];
	uint8_t *ptr = frame;
	uint8_t status = DPP_STATUS_OK;
	uint8_t version = 2;
	uint8_t wrapped2_plaintext[dpp->key_len + 4];
	uint8_t wrapped2[dpp->key_len + 16 + 8];
	size_t wrapped2_len;

	ptr += dpp_build_header(DPP_FRAME_AUTHENTICATION_RESPONSE, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);
	if (dpp->mutual_auth)
		ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
				dpp->peer_boot_hash, 32);
	ptr += dpp_append_point(ptr, DPP_ATTR_RESPONDER_PROTOCOL_KEY,
				dpp->own_proto_public);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);

	/* Wrap up secondary data (R-Auth) */
	wrapped2_len = dpp_append_attr(wrapped2_plaintext,
					DPP_ATTR_RESPONDER_AUTH_TAG,
					dpp->auth_tag, dpp->key_len);
	/*
	 * "Invocations of AES-SIV in the DPP Authentication protocol that
	 * produce ciphertext that is part of an additional AES-SIV invocation
	 * do not use AAD; in other words, the number of AAD components is set
	 * to zero."
	 */
	if (!aes_siv_encrypt(dpp->ke, dpp->key_len, wrapped2_plaintext,
					dpp->key_len + 4, NULL, 0, wrapped2)) {
		l_error("Failed to encrypt wrapped data");
		return;
	}

	wrapped2_len += 16;

	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->k2, dpp->key_len, 4,
			DPP_ATTR_RESPONDER_NONCE, dpp->nonce_len, dpp->r_nonce,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES, (size_t) 1, &dpp->role,
			DPP_ATTR_WRAPPED_DATA, wrapped2_len, wrapped2);

	l_debug("send auth response");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_auth_request_failed(struct dpp_sm *dpp,
					enum dpp_status status,
					void *k1)
{
	uint8_t frame[DPP_HDR_LEN + 128];
	uint8_t *ptr = frame;
	uint8_t version = 2;
	uint8_t s = status;

	ptr += dpp_build_header(DPP_FRAME_AUTHENTICATION_RESPONSE, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &s, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
				dpp->own_boot_hash, 32);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION, &version, 1);
	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			k1, dpp->key_len, 2,
			DPP_ATTR_INITIATOR_NONCE, dpp->nonce_len, dpp->i_nonce,
			DPP_ATTR_RESPONDER_CAPABILITIES,
			(size_t) 1, &dpp->role);

	l_debug("sending auth request failed");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_auth_confirm(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint8_t zero = 0;

	ptr += dpp_build_header(DPP_FRAME_AUTHENTICATION_CONFIRM, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &zero, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_RESPONDER_BOOT_KEY_HASH,
					dpp->peer_boot_hash, 32);
	if (dpp->mutual_auth)
		ptr += dpp_append_attr(ptr, DPP_ATTR_INITIATOR_BOOT_KEY_HASH,
					dpp->own_boot_hash, 32);

	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->ke, dpp->key_len, 1,
			DPP_ATTR_INITIATOR_AUTH_TAG, dpp->key_len,
			dpp->auth_tag);

	l_debug("sending auth confirm");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_config_request(struct dpp_sm *dpp)
{
	const char *json = "{\"name\":\"IWD\",\"wi-fi_tech\":\"infra\","
				"\"netRole\":\"sta\"}";
	size_t json_len = strlen(json);
	uint8_t frame[DPP_HDR_LEN + 512];
	uint8_t *ptr = frame;
	uint8_t *lptr;

	l_getrandom(&dpp->diag_token, 1);
	l_getrandom(dpp->e_nonce, dpp->nonce_len);

	ptr += dpp_build_config_header(true, dpp->diag_token, ptr);

	/* Save length location */
	lptr = ptr;
	ptr += 2;

	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->ke, dpp->key_len, 2,
			DPP_ATTR_ENROLLEE_NONCE, dpp->nonce_len, dpp->e_nonce,
			DPP_ATTR_CONFIGURATION_REQUEST, json_len, json);

	l_put_le16(ptr - lptr - 2, lptr);

	dpp->state = DPP_STATE_CONFIGURING;

	l_debug("sending config request");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_config_response(struct dpp_sm *dpp, uint8_t status)
{
	_auto_(l_free) char *json = NULL;
	uint8_t frame[512];
	size_t json_len;
	uint8_t *ptr = frame;
	uint8_t *lptr;

	ptr += dpp_build_config_header(false, dpp->diag_token, ptr);

	/* Save length location */
	lptr = ptr;
	ptr += 2;

	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);

	/*
	 * There are several failure status codes that can be used (defined in
	 * 6.4.3.1), each with their own set of attributes that should be
	 * included. For now IWD's basic DPP implementation will assume
	 * STATUS_CONFIGURE_FAILURE which only includes the E-Nonce.
	 */
	if (status == DPP_STATUS_OK) {
		json = dpp_configuration_to_json(dpp->config);
		json_len = strlen(json);

		ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
						dpp->ke, dpp->key_len, 2,
						DPP_ATTR_ENROLLEE_NONCE,
						dpp->nonce_len, dpp->e_nonce,
						DPP_ATTR_CONFIGURATION_OBJECT,
						json_len, json);
	} else
		ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
						dpp->ke, dpp->key_len, 2,
						DPP_ATTR_ENROLLEE_NONCE,
						dpp->nonce_len, dpp->e_nonce);

	l_put_le16(ptr - lptr - 2, lptr);

	l_debug("sending config response");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_config_result(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint8_t zero = 0;

	memset(frame, 0, sizeof(frame));

	ptr += dpp_build_header(DPP_FRAME_CONFIGURATION_RESULT, ptr);
	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->ke, dpp->key_len, 2,
			DPP_ATTR_STATUS, (size_t) 1, &zero,
			DPP_ATTR_ENROLLEE_NONCE, dpp->nonce_len, dpp->e_nonce);

	l_debug("sending config result");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_exchange_request(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint16_t group;

	memset(frame, 0, sizeof(frame));

	l_put_le16(l_ecc_curve_get_ike_group(dpp->curve), &group);

	ptr += dpp_build_header(DPP_FRAME_PKEX_VERSION1_XCHG_REQUEST, ptr);

	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION,
				&dpp->pkex_version, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_FINITE_CYCLIC_GROUP,
				&group, 2);

	if (dpp->pkex_id)
		ptr += dpp_append_attr(ptr, DPP_ATTR_CODE_IDENTIFIER,
					dpp->pkex_id, strlen(dpp->pkex_id));

	ptr += dpp_append_point(ptr, DPP_ATTR_ENCRYPTED_KEY, dpp->pkex_m);

	dpp->state = DPP_STATE_PKEX_EXCHANGE;

	l_debug("sending PKEX v1 exchange request");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_exchange_response(struct dpp_sm *dpp,
						struct l_ecc_point *n)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint16_t group;
	uint8_t status = DPP_STATUS_OK;

	memset(frame, 0, sizeof(frame));

	l_put_le16(l_ecc_curve_get_ike_group(dpp->curve), &group);

	ptr += dpp_build_header(DPP_FRAME_PKEX_XCHG_RESPONSE, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);

	if (dpp->pkex_id)
		ptr += dpp_append_attr(ptr, DPP_ATTR_CODE_IDENTIFIER,
					dpp->pkex_id, strlen(dpp->pkex_id));

	ptr += dpp_append_point(ptr, DPP_ATTR_ENCRYPTED_KEY, n);

	dpp->state = DPP_STATE_PKEX_COMMIT_REVEAL;

	l_debug("sending PKEX exchange response");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_bad_group(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint16_t group;
	uint8_t status = DPP_STATUS_BAD_GROUP;

	memset(frame, 0, sizeof(frame));

	l_put_le16(l_ecc_curve_get_ike_group(dpp->curve), &group);

	ptr += dpp_build_header(DPP_FRAME_PKEX_XCHG_RESPONSE, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION,
				&dpp->pkex_version, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_FINITE_CYCLIC_GROUP, &group, 2);

	l_debug("sending PKEX bad group");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_bad_code(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 256];
	uint8_t *ptr = frame;
	uint8_t status = DPP_STATUS_BAD_CODE;

	memset(frame, 0, sizeof(frame));

	ptr += dpp_build_header(DPP_FRAME_PKEX_XCHG_RESPONSE, ptr);
	ptr += dpp_append_attr(ptr, DPP_ATTR_STATUS, &status, 1);
	ptr += dpp_append_attr(ptr, DPP_ATTR_PROTOCOL_VERSION,
				&dpp->pkex_version, 1);
	if (dpp->pkex_id)
		ptr += dpp_append_attr(ptr, DPP_ATTR_CODE_IDENTIFIER,
					dpp->pkex_id, strlen(dpp->pkex_id));

	l_debug("sending PKEX bad code");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_commit_reveal_request(struct dpp_sm *dpp)
{
	uint8_t frame[DPP_HDR_LEN + 512];
	uint8_t *ptr = frame;
	uint8_t a_pub[L_ECC_POINT_MAX_BYTES];
	ssize_t a_len;

	memset(frame, 0, sizeof(frame));

	a_len = l_ecc_point_get_data(dpp->boot_public, a_pub, sizeof(a_pub));

	ptr += dpp_build_header(DPP_FRAME_PKEX_COMMIT_REVEAL_REQUEST, ptr);

	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->z, dpp->z_len, 2,
			DPP_ATTR_BOOTSTRAPPING_KEY, a_len, a_pub,
			DPP_ATTR_INITIATOR_AUTH_TAG, dpp->u_len, dpp->u);

	dpp->state = DPP_STATE_PKEX_COMMIT_REVEAL;

	l_debug("sending PKEX commit reveal request");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_send_pkex_commit_reveal_response(struct dpp_sm *dpp,
						const uint8_t *v, size_t v_len)
{
	uint8_t frame[DPP_HDR_LEN + 512];
	uint8_t *ptr = frame;
	uint8_t b_pub[L_ECC_POINT_MAX_BYTES];
	size_t b_len;

	memset(frame, 0, sizeof(frame));

	b_len = l_ecc_point_get_data(dpp->boot_public, b_pub, sizeof(b_pub));

	ptr += dpp_build_header(DPP_FRAME_PKEX_COMMIT_REVEAL_RESPONSE, ptr);
	ptr += dpp_append_wrapped_data(frame, sizeof(frame), ptr,
			dpp->z, dpp->z_len, 2,
			DPP_ATTR_BOOTSTRAPPING_KEY, b_len, b_pub,
			DPP_ATTR_RESPONDER_AUTH_TAG, v_len, v);

	l_debug("sending PKEX commit reveal response");

	dpp_try_write(dpp, frame, ptr - frame);
}

static void dpp_process_pkex_exchange_request(struct dpp_sm *dpp,
						struct l_ecc_point *m)
{
	_auto_(l_ecc_point_free) struct l_ecc_point *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *qr = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *qi = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *k = NULL;

	l_debug("");

	/* Qi = H(MAC-Initiator | [identifier | ] code) * Pi */
	qi = dpp_derive_qi(dpp->curve, dpp->pkex_key, dpp->pkex_id,
				dpp->mac_initiator);
	if (!qi) {
		l_debug("could not derive Qi");
		return;
	}

	/* X' = M - Qi */
	dpp->y_or_x = l_ecc_point_new(dpp->curve);

	l_ecc_point_inverse(qi);
	l_ecc_point_add(dpp->y_or_x, m, qi);

	/*
	 * "The resulting ephemeral key, denoted X’, is checked whether it is
	 * the point-at-infinity. If it is not valid, the protocol silently
	 * fails"
	 */
	if (l_ecc_point_is_infinity(dpp->y_or_x)) {
		l_debug("X' is at infinity, ignore message");
		dpp_failed(dpp);
		return;
	}

	qr = dpp_derive_qr(dpp->curve, dpp->pkex_key, dpp->pkex_id,
				dpp->mac_responder);
	if (!qr || l_ecc_point_is_infinity(qr)) {
		l_debug("Qr did not derive");
		l_ecc_point_free(dpp->y_or_x);
		dpp->y_or_x = NULL;
		goto bad_code;
	}

	/*
	 * "The Responder then generates a random ephemeral keypair, y/Y,
	 * encrypts Y with Qr to obtain the result, denoted N."
	 */
	l_ecdh_generate_key_pair(dpp->curve, &dpp->pkex_private,
					&dpp->pkex_public);

	/* N = Y + Qr */
	n = l_ecc_point_new(dpp->curve);

	l_ecc_point_add(n, dpp->pkex_public, qr);

	/* K = y * X' */

	k = l_ecc_point_new(dpp->curve);

	l_ecc_point_multiply(k, dpp->pkex_private, dpp->y_or_x);

	/* z = HKDF(<>, info | M.x | N.x | code, K.x) */
	dpp_derive_z(dpp->mac_initiator, dpp->mac_responder, n, m, k,
			dpp->pkex_key, dpp->pkex_id, dpp->z, &dpp->z_len);

	dpp_send_pkex_exchange_response(dpp, n);

	return;

bad_code:
	dpp_send_pkex_bad_code(dpp);
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

	/*
	 * Presence/exchange are special cases because 802.11 encapsulation
	 * requires going off channel for specific amounts of time. We cannot
	 * easily start a timer within the common code and try and remained
	 * synced with the offchannel callbacks.
	 * Instead let the offchannel callbacks dictate when these frames
	 * are sent out. All other write operations are driven by the reception
	 * of other frames.
	 */
	if (dpp->state == DPP_STATE_PRESENCE && !dpp->initiator)
		dpp_send_presence(dpp);
	else if ( dpp->state == DPP_STATE_PKEX_EXCHANGE && dpp->initiator)
		dpp_send_pkex_exchange_request(dpp);
	else if (dpp->frame_pending) {
		dpp->write(dpp->frame_pending, dpp->frame_len, dpp->user_data);

		l_free(dpp->frame_pending);
		dpp->frame_pending = NULL;
	}
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

	if (dpp->initiator)
		dpp_send_auth_request(dpp);

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

	/*
	 * An Enrollee acting in a Responder role uses DPP Presence
	 * Announcement to signal a potential Configurator that it is
	 * ready to engage in a DPP exchange
	 */
	if (dpp->role == DPP_CAPABILITY_ENROLLEE) {
		if (!dpp->skip_presence)
			dpp_send_presence(dpp);
	}

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

	/* This was set after the key was requested, send the response now */
	if (dpp->state == DPP_STATE_PKEX_EXCHANGE)
		dpp_process_pkex_exchange_request(dpp, dpp->peer_encr_key);
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

	dpp_send_pkex_exchange_request(dpp);

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

static void dpp_handle_presence_announcement(struct dpp_sm *dpp,
						const uint8_t *frame,
						size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const void *r_boot = NULL;
	size_t r_boot_len = 0;
	uint8_t hash[32];

	l_debug("Presence announcement");

	/* Must be a configurator, in an initiator role, in PRESENCE state */
	if (dpp->state != DPP_STATE_PRESENCE)
		return;

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot = data;
			r_boot_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_boot || r_boot_len != 32) {
		l_debug("No responder boot hash");
		return;
	}

	/* Hash what we have for the peer and check its our enrollee */
	dpp_hash(L_CHECKSUM_SHA256, hash, 2, "chirp", strlen("chirp"),
			dpp->peer_asn1, dpp->peer_asn1_len);

	if (memcmp(hash, r_boot, sizeof(hash))) {
		l_debug("Peers boot hash did not match");
		return;
	}

	if (dpp->event_cb)
		dpp->event_cb(DPP_EVENT_PEER_ACCEPTED, NULL, dpp->user_data);

	dpp->state = DPP_STATE_AUTHENTICATING;

	dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);

	dpp_start_authentication(dpp);
}

static void dpp_handle_auth_request(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const uint8_t *r_boot = NULL;
	const uint8_t *i_boot = NULL;
	const uint8_t *i_proto = NULL;
	const void *wrapped = NULL;
	const uint8_t *i_nonce = NULL;
	uint8_t i_capa = 0;
	size_t r_boot_len = 0, i_proto_len = 0, wrapped_len = 0;
	size_t i_nonce_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *m = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	struct l_ecc_point *bi = NULL;
	uint64_t k1[L_ECC_MAX_DIGITS];
	const void *ad0 = frame;
	const void *ad1 = frame + 6;

	if (dpp->state != DPP_STATE_PRESENCE &&
				dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	l_debug("authenticate request");

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_BOOT_KEY_HASH:
			i_boot = data;
			/*
			 * This attribute is required by the spec, but only
			 * used for mutual authentication.
			 */
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot = data;
			r_boot_len = len;
			break;
		case DPP_ATTR_INITIATOR_PROTOCOL_KEY:
			i_proto = data;
			i_proto_len = len;
			break;
		case DPP_ATTR_WRAPPED_DATA:
			/* I-Nonce/I-Capabilities part of wrapped data */
			wrapped = data;
			wrapped_len = len;
			break;

		/* Optional attributes */
		case DPP_ATTR_PROTOCOL_VERSION:
			if (l_get_u8(data) != 2) {
				l_debug("Protocol version did not match");
				return;
			}

			break;

		case DPP_ATTR_CHANNEL:
			if (len != 2)
				return;

			/*
			 * Not part of the spec, but IWD puts a requirement on
			 * enrollees that they must come to the configurators
			 * channel to preserve performance
			 */
			if (dpp->role == DPP_CAPABILITY_CONFIGURATOR)
				break;

			if (dpp->event_cb)
				dpp->event_cb(DPP_EVENT_CHANNEL_SWITCH, data,
						dpp->user_data);

			break;
		default:
			break;
		}
	}

	if (!r_boot || !i_boot || !i_proto || !wrapped) {
		l_debug("missing attributes");
		goto auth_request_failed;
	}

	if (r_boot_len != 32 || memcmp(dpp->own_boot_hash,
					r_boot, r_boot_len)) {
		l_debug("Responder boot key hash failed to verify");
		goto auth_request_failed;
	}

	dpp->peer_proto_public = l_ecc_point_from_data(dpp->curve,
						L_ECC_POINT_TYPE_FULL,
						i_proto, i_proto_len);
	if (!dpp->peer_proto_public) {
		l_debug("Initiators protocol key invalid");
		goto auth_request_failed;
	}

	m = dpp_derive_k1(dpp->peer_proto_public, dpp->boot_private, k1);
	if (!m) {
		l_debug("deriving k1/m failed");
		goto auth_request_failed;
	}

	unwrapped = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1,
			k1, dpp->key_len, wrapped, wrapped_len, &wrapped_len);
	if (!unwrapped) {
		l_debug("failed to unwrap data");
		goto auth_request_failed;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_NONCE:
			i_nonce = data;
			i_nonce_len = len;
			break;
		case DPP_ATTR_INITIATOR_CAPABILITIES:
			/*
			 * "If the Responder is not capable of supporting the
			 * role indicated by the Initiator, it shall respond
			 * with a DPP Authentication Response frame indicating
			 * failure by adding the DPP Status field set to
			 * STATUS_NOT_COMPATIBLE"
			 */
			i_capa = l_get_u8(data);

			if (!dpp_check_roles(dpp, i_capa)) {
				l_debug("Peer does not support required role");
				dpp_send_auth_request_failed(dpp,
						DPP_STATUS_NOT_COMPATIBLE, k1);
				goto auth_request_failed;
			}

			break;
		default:
			break;
		}
	}

	if (i_nonce_len != dpp->nonce_len) {
		l_debug("I-Nonce has unexpected length %zu", i_nonce_len);
		goto auth_request_failed;
	}

	memcpy(dpp->i_nonce, i_nonce, i_nonce_len);

	if (dpp->mutual_auth) {
		l = dpp_derive_lr(dpp->boot_private, dpp->proto_private,
					dpp->peer_boot_public);
		bi = dpp->peer_boot_public;
	}

	/* Derive keys k2, ke, and R-Auth for authentication response */

	n = dpp_derive_k2(dpp->peer_proto_public, dpp->proto_private, dpp->k2);
	if (!n) {
		l_debug("deriving k2/n failed");
		goto auth_request_failed;
	}

	l_getrandom(dpp->r_nonce, dpp->nonce_len);

	if (!dpp_derive_ke(dpp->i_nonce, dpp->r_nonce, m, n, l, dpp->ke)) {
		l_debug("deriving ke failed");
		goto auth_request_failed;
	}

	if (!dpp_derive_r_auth(dpp->i_nonce, dpp->r_nonce, dpp->nonce_len,
				dpp->peer_proto_public, dpp->own_proto_public,
				bi, dpp->boot_public, dpp->auth_tag)) {
		l_debug("deriving R_auth failed");
		goto auth_request_failed;
	}

	dpp->state = DPP_STATE_AUTHENTICATING;

	dpp_reset_protocol_timer(dpp, DPP_AUTH_PROTO_TIMEOUT);

	dpp_send_auth_response(dpp);

	return;

auth_request_failed:
	l_debug("handle auth request failed");
	dpp->state = DPP_STATE_PRESENCE;
	dpp_free_auth_data(dpp);
}

static void dpp_handle_auth_response(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const void *r_boot_hash = NULL;
	const void *r_proto = NULL;
	size_t r_proto_len = 0;
	const void *wrapped = NULL;
	size_t wrapped_len;
	_auto_(l_free) uint8_t *unwrapped1 = NULL;
	_auto_(l_free) uint8_t *unwrapped2 = NULL;
	const void *r_nonce = NULL;
	const void *i_nonce = NULL;
	const void *r_auth = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *r_proto_key = NULL;
	_auto_(l_ecc_scalar_free) struct l_ecc_scalar *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	struct l_ecc_point *bi = NULL;
	const void *ad0 = frame;
	const void *ad1 = frame + 6;
	uint64_t r_auth_derived[L_ECC_MAX_DIGITS];

	l_debug("Authenticate response");

	if (dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			if (len != 1)
				return;

			status = l_get_u8(data);
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot_hash = data;
			break;
		case DPP_ATTR_RESPONDER_PROTOCOL_KEY:
			r_proto = data;
			r_proto_len = len;
			break;
		case DPP_ATTR_PROTOCOL_VERSION:
			if (len != 1 || l_get_u8(data) != 2)
				return;
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (status != DPP_STATUS_OK || !r_boot_hash || !r_proto || !wrapped) {
		l_debug("Auth response bad status or missing attributes");
		return;
	}

	r_proto_key = l_ecc_point_from_data(dpp->curve, L_ECC_POINT_TYPE_FULL,
						r_proto, r_proto_len);
	if (!r_proto_key) {
		l_debug("Peers protocol key was invalid");
		return;
	}

	n = dpp_derive_k2(r_proto_key, dpp->proto_private, dpp->k2);

	unwrapped1 = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1, dpp->k2,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped1) {
		l_debug("Failed to unwrap primary data");
		return;
	}

	wrapped = NULL;

	dpp_attr_iter_init(&iter, unwrapped1, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_NONCE:
			if (len != dpp->nonce_len)
				return;

			r_nonce = data;
			break;
		case DPP_ATTR_INITIATOR_NONCE:
			if (len != dpp->nonce_len)
				return;

			i_nonce = data;
			break;
		case DPP_ATTR_RESPONDER_CAPABILITIES:
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_nonce || !i_nonce || !wrapped) {
		l_debug("Wrapped data missing attributes");
		return;
	}

	if (dpp->mutual_auth) {
		l = dpp_derive_li(dpp->peer_boot_public, r_proto_key,
					dpp->boot_private);
		bi = dpp->boot_public;
	}

	if (!dpp_derive_ke(i_nonce, r_nonce, dpp->m, n, l, dpp->ke)) {
		l_debug("Failed to derive ke");
		return;
	}

	unwrapped2 = dpp_unwrap_attr(NULL, 0, NULL, 0, dpp->ke, dpp->key_len,
					wrapped, wrapped_len, &wrapped_len);
	if (!unwrapped2) {
		l_debug("Failed to unwrap secondary data");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped2, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_RESPONDER_AUTH_TAG:
			if (len != dpp->key_len)
				return;

			r_auth = data;
			break;
		default:
			break;
		}
	}

	if (!r_auth) {
		l_debug("R-Auth was not in secondary wrapped data");
		return;
	}

	if (!dpp_derive_r_auth(i_nonce, r_nonce, dpp->nonce_len,
				dpp->own_proto_public, r_proto_key, bi,
				dpp->peer_boot_public, r_auth_derived)) {
		l_debug("Failed to derive r_auth");
		return;
	}

	if (memcmp(r_auth, r_auth_derived, dpp->key_len)) {
		l_debug("R-Auth did not verify");
		return;
	}

	if (!dpp_derive_i_auth(r_nonce, i_nonce, dpp->nonce_len,
				r_proto_key, dpp->own_proto_public,
				dpp->peer_boot_public, bi, dpp->auth_tag)) {
		l_debug("Could not derive I-Auth");
		return;
	}

	dpp_send_auth_confirm(dpp);

	if (dpp->role == DPP_CAPABILITY_ENROLLEE)
		dpp_send_config_request(dpp);
}

static void dpp_handle_auth_confirm(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const uint8_t *r_boot_hash = NULL;
	const void *wrapped = NULL;
	const uint8_t *i_auth = NULL;
	size_t i_auth_len;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	size_t wrapped_len = 0;
	uint64_t i_auth_check[L_ECC_MAX_DIGITS];
	const void *unwrap_key;
	const void *ad0 = frame;
	const void *ad1 = frame + 6;
	struct l_ecc_point *bi = NULL;

	if (dpp->state != DPP_STATE_AUTHENTICATING)
		return;

	l_debug("authenticate confirm");

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			status = l_get_u8(data);
			break;
		case DPP_ATTR_RESPONDER_BOOT_KEY_HASH:
			r_boot_hash = data;
			/*
			 * Spec requires this, but does not mention if anything
			 * is to be done with it.
			 */
			break;
		case DPP_ATTR_INITIATOR_BOOT_KEY_HASH:
			/* No mutual authentication */
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!r_boot_hash || !wrapped) {
		l_debug("Attributes missing from authenticate confirm");
		return;
	}

	/*
	 * "The Responder obtains the DPP Authentication Confirm frame and
	 * checks the value of the DPP Status field. If the value of the DPP
	 * Status field is STATUS_NOT_COMPATIBLE or STATUS_AUTH_FAILURE, the
	 * Responder unwraps the wrapped data portion of the frame using k2"
	 */
	if (status == DPP_STATUS_OK)
		unwrap_key = dpp->ke;
	else if (status == DPP_STATUS_NOT_COMPATIBLE ||
				status == DPP_STATUS_AUTH_FAILURE)
		unwrap_key = dpp->k2;
	else
		goto auth_confirm_failed;

	unwrapped = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1,
			unwrap_key, dpp->key_len, wrapped, wrapped_len,
			&wrapped_len);
	if (!unwrapped)
		goto auth_confirm_failed;

	if (status != DPP_STATUS_OK) {
		/*
		 * "If unwrapping is successful, the Responder should generate
		 * an alert indicating the reason for the protocol failure."
		 */
		l_debug("Authentication failed due to status %s",
				status == DPP_STATUS_NOT_COMPATIBLE ?
				"NOT_COMPATIBLE" : "AUTH_FAILURE");
		goto auth_confirm_failed;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_INITIATOR_AUTH_TAG:
			i_auth = data;
			i_auth_len = len;
			break;
		case DPP_ATTR_RESPONDER_NONCE:
			/* Only if error */
			break;
		default:
			break;
		}
	}

	if (!i_auth || i_auth_len != dpp->key_len) {
		l_debug("I-Auth missing from wrapped data");
		goto auth_confirm_failed;
	}

	if (dpp->mutual_auth)
		bi = dpp->peer_boot_public;

	dpp_derive_i_auth(dpp->r_nonce, dpp->i_nonce, dpp->nonce_len,
				dpp->own_proto_public, dpp->peer_proto_public,
				dpp->boot_public, bi, i_auth_check);

	if (memcmp(i_auth, i_auth_check, i_auth_len)) {
		l_error("I-Auth did not verify");
		goto auth_confirm_failed;
	}

	l_debug("Authentication successful");

	if (dpp->role == DPP_CAPABILITY_ENROLLEE)
		dpp_send_config_request(dpp);

	return;

auth_confirm_failed:
	dpp->state = DPP_STATE_PRESENCE;
	dpp_free_auth_data(dpp);
}

/* Parses the config header (GAS) and returns the start of the payload */
static const uint8_t *dpp_parse_config_header(uint8_t action,
						const uint8_t *data, size_t len,
						uint8_t *diag_token_out,
						uint16_t *status_out,
						uint16_t *comeback_out,
						size_t *attr_len_out)
{
	uint8_t adv_protocol_id[] = { 0xDD, 0x05, 0x50, 0x6F,
					0x9A, 0x1A, 0x01 };
	uint8_t diag_token;
	uint16_t status = 0;
	uint16_t comeback = 0;
	uint16_t attr_len;
	const uint8_t *ptr = data;

	if (len < 1)
		return NULL;

	diag_token = *ptr++;

	switch (action) {
	case DPP_ACTION_GAS_REQUEST:
		if (len < 12)
			return NULL;
		break;
	case DPP_ACTION_GAS_RESPONSE:
		if (len < 14)
			return NULL;

		status = l_get_le16(ptr);
		ptr += 2;
		comeback = l_get_le16(ptr);
		ptr += 2;

		break;
	default:
		return NULL;
	}

	if (*ptr++ != IE_TYPE_ADVERTISEMENT_PROTOCOL)
		return NULL;

	/* Length of advertisement protocol fields */
	if (*ptr++ != 0x08)
		return NULL;
	/*
	 * Unfortunately wpa_supplicant hard codes 0x7f as the Query Response
	 * Info so we need to handle both cases.
	 */
	if (*ptr != 0x7f && *ptr != 0x00)
		return NULL;
	ptr++;

	if (memcmp(ptr, adv_protocol_id, sizeof(adv_protocol_id)))
		return NULL;

	ptr += sizeof(adv_protocol_id);

	attr_len = l_get_le16(ptr);
	ptr += 2;

	/* Check the attribute length matches the total length */
	if (attr_len > len - (ptr - data))
		return false;

	if (diag_token_out)
		*diag_token_out = diag_token;

	if (action == DPP_ACTION_GAS_RESPONSE) {
		if (status_out)
			*status_out = status;
		if (comeback_out)
			*comeback_out = comeback;
	}

	if (attr_len_out)
		*attr_len_out = attr_len;

	return ptr;
}

static void dpp_handle_config_request(struct dpp_sm *dpp, const uint8_t *frame,
				size_t frame_len)
{
	const uint8_t *attrs;
	size_t attrs_len;
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	const uint8_t *data;
	size_t len;
	const char *json = NULL;
	size_t json_len = 0;
	struct json_contents *c;
	const uint8_t *wrapped = NULL;
	const uint8_t *e_nonce = NULL;
	size_t wrapped_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	struct json_iter jsiter;
	_auto_(l_free) char *tech = NULL;
	_auto_(l_free) char *role = NULL;

	attrs = dpp_parse_config_header(DPP_ACTION_GAS_REQUEST, frame,
					frame_len, &dpp->diag_token,
					NULL, NULL, &attrs_len);
	if (!attrs)
		return;

	if (dpp->state != DPP_STATE_AUTHENTICATING) {
		l_debug("Configuration request in wrong state");
		return;
	}

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	dpp_attr_iter_init(&iter, attrs, attrs_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/* Wrapped data should be only attribute */
			return;
		}
	}

	if (!wrapped) {
		l_debug("Wrapped data missing");
		return;
	}

	unwrapped = dpp_unwrap_attr(NULL, 0, NULL, 0, dpp->ke,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_ENROLLEE_NONCE:
			if (len != dpp->nonce_len)
				break;

			e_nonce = data;
			break;
		case DPP_ATTR_CONFIGURATION_REQUEST:
			json = (const char *)data;
			json_len = len;
			break;
		default:
			break;
		}
	}

	if (!json || !e_nonce) {
		l_debug("No configuration object in response");
		return;
	}

	c = json_contents_new(json, json_len);
	if (!c) {
		json_contents_free(c);
		return;
	}

	json_iter_init(&jsiter, c);

	/*
	 * Check mandatory values (Table 7). There isn't much that can be done
	 * with these, but the spec requires they be included.
	 */
	if (!json_iter_parse(&jsiter,
			JSON_MANDATORY("name", JSON_STRING, NULL),
			JSON_MANDATORY("wi-fi_tech", JSON_STRING, &tech),
			JSON_MANDATORY("netRole", JSON_STRING, &role),
			JSON_UNDEFINED))
		goto configure_failure;

	if (strcmp(tech, "infra"))
		goto configure_failure;

	if (strcmp(role, "sta"))
		goto configure_failure;

	json_contents_free(c);

	memcpy(dpp->e_nonce, e_nonce, dpp->nonce_len);

	dpp->state = DPP_STATE_CONFIGURING;

	dpp_send_config_response(dpp, DPP_STATUS_OK);

	return;

configure_failure:
	dpp_send_config_response(dpp, DPP_STATUS_CONFIGURE_FAILURE);
	/*
	 * The other peer is still authenticated, and can potentially send
	 * additional requests so keep this session alive.
	 */
}

static void dpp_handle_config_response(struct dpp_sm *dpp, const uint8_t *frame,
					size_t frame_len)
{
	const uint8_t *attrs;
	size_t attrs_len;
	uint16_t status;
	uint8_t diag_token;
	uint16_t comeback;
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const char *json = NULL;
	size_t json_len = 0;
	int dstatus = -1;
	const uint8_t *wrapped = NULL;
	const uint8_t *e_nonce = NULL;
	size_t wrapped_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;

	l_debug("config response");

	attrs = dpp_parse_config_header(DPP_ACTION_GAS_RESPONSE, frame,
					frame_len, &diag_token, &status,
					&comeback, &attrs_len);
	if (!attrs || diag_token != dpp->diag_token || status != 0) {
		l_debug("failed to parse header");
		return;
	}

	/* TODO: comeback delay */
	if (comeback != 0) {
		l_debug("comeback not zero");
		return;
	}

	if (dpp->state != DPP_STATE_CONFIGURING) {
		l_debug("state not configuring");
		return;
	}


	dpp_attr_iter_init(&iter, attrs, attrs_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			dstatus = l_get_u8(data);
			break;
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/*
			 * TODO: CSR Attribute
			 */
			break;
		}
	}

	if (dstatus != DPP_STATUS_OK || !wrapped) {
		l_debug("Bad status or missing attributes");
		return;
	}

	unwrapped = dpp_unwrap_attr(attrs, wrapped - attrs - 4, NULL, 0, dpp->ke,
					dpp->key_len, wrapped, wrapped_len,
					&wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_ENROLLEE_NONCE:
			if (len != dpp->nonce_len)
				break;

			if (memcmp(data, dpp->e_nonce, dpp->nonce_len))
				break;

			e_nonce = data;
			break;
		case DPP_ATTR_CONFIGURATION_OBJECT:
			json = (const char *)data;
			json_len = len;
			break;
		default:
			break;
		}
	}

	if (!json || !e_nonce) {
		l_debug("No configuration object in response");
		return;
	}

	dpp->config = dpp_parse_configuration_object(json, json_len);
	if (!dpp->config) {
		l_error("Configuration object did not parse");
		return;
	}

	dpp_send_config_result(dpp);

	l_timeout_remove(dpp->timeout);
	dpp->timeout = NULL;

	if (dpp->event_cb)
		dpp->event_cb(DPP_EVENT_SUCCESS, NULL, dpp->user_data);
}

static void dpp_handle_config_result_frame(struct dpp_sm *dpp,
						const uint8_t *frame,
						size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	int status = -1;
	const void *e_nonce = NULL;
	const void *wrapped = NULL;
	size_t wrapped_len;
	_auto_(l_free) void *unwrapped = NULL;
	const void *ad0 = frame;
	const void *ad1 = frame + 6;

	if (dpp->state != DPP_STATE_CONFIGURING)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			/* Wrapped data should be only attribute */
			return;
		}
	}

	if (!wrapped) {
		l_debug("No wrapped data in config result");
		return;
	}

	unwrapped = dpp_unwrap_attr(ad0, 6, ad1, wrapped - 4 - ad1,
					dpp->ke, dpp->key_len, wrapped,
					wrapped_len, &wrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap DPP configuration result");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, wrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			status = l_get_u8(data);
			break;
		case DPP_ATTR_ENROLLEE_NONCE:
			e_nonce = data;
			break;
		default:
			break;
		}
	}

	l_timeout_remove(dpp->timeout);
	dpp->timeout = NULL;

	if (!dpp->event_cb)
		return;

	if (status != DPP_STATUS_OK || !e_nonce)
		dpp_failed(dpp);
	else
		dpp->event_cb(DPP_EVENT_SUCCESS, NULL, dpp->user_data);
}

static void dpp_pkex_bad_group(struct dpp_sm *dpp, uint16_t group)
{
	uint16_t own_group = l_ecc_curve_get_ike_group(dpp->curve);

	/*
	 * TODO: The spec allows group negotiation, but it is not yet
	 *       implemented.
	 */
	if (!group)
		return;
	/*
	 * Section 5.6.2
	 * "If the Responder's offered group offers less security
	 * than the Initiator's offered group, then the Initiator should
	 * ignore this message"
	 */
	if (group < own_group) {
		l_debug("Offered group %u is less secure, ignoring",
				group);
		return;
	}
	/*
	 * Section 5.6.2
	 * "If the Responder's offered group offers equivalent or better
	 * security than the Initiator's offered group, then the
	 * Initiator may choose to abort its original request and try
	 * another exchange using the group offered by the Responder"
	 */
	if (group >= own_group) {
		l_debug("Offered group %u is the same or more secure, "
			" but group negotiation is not supported", group);
		return;
	}
}

static void dpp_pkex_bad_code(struct dpp_sm *dpp)
{
	_auto_(l_ecc_point_free) struct l_ecc_point *qr = NULL;

	qr = dpp_derive_qr(dpp->curve, dpp->pkex_key, dpp->pkex_id,
				dpp->mac_responder);
	if (!qr || l_ecc_point_is_infinity(qr)) {
		l_debug("Qr computed to zero, new code should be provisioned");
		return;
	}

	l_debug("Qr computed successfully but responder indicated otherwise");
}

static void dpp_handle_pkex_exchange_response(struct dpp_sm *dpp,
						const uint8_t *frame,
						size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const uint8_t *status = NULL;
	uint8_t version = 0;
	const void *identifier = NULL;
	size_t identifier_len = 0;
	const void *key = NULL;
	size_t key_len = 0;
	uint16_t group = 0;
	_auto_(l_ecc_point_free) struct l_ecc_point *n = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *j = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *qr = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *k = NULL;

	l_debug("PKEX exchange response");

	if (dpp->state != DPP_STATE_PKEX_EXCHANGE)
		return;

	if (dpp->role != DPP_CAPABILITY_ENROLLEE)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_STATUS:
			if (len != 1)
				return;

			status = data;
			break;
		case DPP_ATTR_PROTOCOL_VERSION:
			if (len != 1)
				return;

			version = l_get_u8(data);
			break;
		case DPP_ATTR_CODE_IDENTIFIER:
			identifier = data;
			identifier_len = len;
			break;
		case DPP_ATTR_ENCRYPTED_KEY:
			if (len != dpp->key_len * 2)
				return;

			key = data;
			key_len = len;
			break;
		case DPP_ATTR_FINITE_CYCLIC_GROUP:
			if (len != 2)
				return;

			group = l_get_le16(data);
			break;
		default:
			break;
		}
	}

	if (!status) {
		l_debug("No status attribute, ignoring");
		return;
	}

	if (!key) {
		l_debug("No encrypted key, ignoring");
		return;
	}

	if (*status != DPP_STATUS_OK)
		goto handle_status;

	if (dpp->pkex_id) {
		if (!identifier || identifier_len != strlen(dpp->pkex_id) ||
					memcmp(dpp->pkex_id, identifier,
						identifier_len)) {
			l_debug("mismatch identifier, ignoring");
			return;
		}
	}

	if (version && version != dpp->pkex_version) {
		l_debug("PKEX version does not match, igoring");
		return;
	}

	n = l_ecc_point_from_data(dpp->curve, L_ECC_POINT_TYPE_FULL,
					key, key_len);
	if (!n) {
		l_debug("failed to parse peers encrypted key");
		goto failed;
	}

	/*
	 * TODO: PKEX protocol version 2 does not require the initiator or
	 *       responder MAC addresses. If using protocol version 2 there will
	 *       be no requirement for the encapsulating protocol to set this.
	 *
	 * Until then (and always for protocol 1) the encapsulating protocol
	 * must set the peers address in the PEER_ACCEPTED callback for PKEX.
	 */
	if (dpp->event_cb)
		dpp->event_cb(DPP_EVENT_PEER_ACCEPTED, NULL, dpp->user_data);

	if (L_WARN_ON(!dpp->mac_responder))
		goto failed;

	qr = dpp_derive_qr(dpp->curve, dpp->pkex_key, dpp->pkex_id,
				dpp->mac_responder);
	if (!qr)
		goto failed;

	dpp->y_or_x = l_ecc_point_new(dpp->curve);

	/* Y' = N - Qr */
	l_ecc_point_inverse(qr);
	l_ecc_point_add(dpp->y_or_x, n, qr);

	/*
	 * "The resulting ephemeral key, denoted Y’, is then checked whether it
	 * is the point-at-infinity. If it is not valid, the protocol ends
	 * unsuccessfully"
	 */
	if (l_ecc_point_is_infinity(dpp->y_or_x)) {
		l_debug("Y' computed to infinity, failing");
		goto failed;
	}

	k = l_ecc_point_new(dpp->curve);

	/* K = Y' * x */
	l_ecc_point_multiply(k, dpp->pkex_private, dpp->y_or_x);

	dpp_derive_z(dpp->mac_initiator, dpp->mac_responder, n, dpp->pkex_m, k,
				dpp->pkex_key, dpp->pkex_id,
				dpp->z, &dpp->z_len);

	/* J = a * Y' */
	j = l_ecc_point_new(dpp->curve);

	l_ecc_point_multiply(j, dpp->boot_private, dpp->y_or_x);

	if (!dpp_derive_u(j, dpp->mac_initiator, dpp->boot_public, dpp->y_or_x,
				dpp->pkex_public, dpp->u, &dpp->u_len)) {
		l_debug("failed to compute u");
		goto failed;
	}

	dpp_send_pkex_commit_reveal_request(dpp);

	return;

handle_status:
	switch (*status) {
	case DPP_STATUS_BAD_GROUP:
		dpp_pkex_bad_group(dpp, group);
		break;
	case DPP_STATUS_BAD_CODE:
		dpp_pkex_bad_code(dpp);
		break;
	default:
		l_debug("Unhandled status %u", *status);
		break;
	}

failed:
	dpp_failed(dpp);
}

static void dpp_handle_pkex_v1_exchange_request(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	uint8_t version = 0;
	uint16_t group = 0;
	const void *id = NULL;
	size_t id_len = 0;
	const void *key = NULL;
	size_t key_len = 0;
	_auto_(l_ecc_point_free) struct l_ecc_point *m = NULL;

	l_debug("PKEX exchange request");

	if (dpp->state != DPP_STATE_PKEX_EXCHANGE)
		return;

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_PROTOCOL_VERSION:
			if (len != 1)
				return;

			version = l_get_u8(data);
			break;
		case DPP_ATTR_FINITE_CYCLIC_GROUP:
			if (len != 2)
				return;

			group = l_get_le16(data);
			break;
		case DPP_ATTR_CODE_IDENTIFIER:
			id = data;
			id_len = len;
			break;
		case DPP_ATTR_ENCRYPTED_KEY:
			key = data;
			key_len = len;
			break;
		default:
			break;
		}
	}

	if (!key || !group) {
		l_debug("initiator did not provide group or key, ignoring");
		return;
	}

	if (group != l_ecc_curve_get_ike_group(dpp->curve)) {
		l_debug("initiator is not using the same group");
		goto bad_group;
	}

	/*
	 * If the group isn't the same the key length won't match, so check
	 * this here after we've determined the groups are equal
	 */
	if (key_len != dpp->key_len * 2) {
		l_debug("Unexpected encrypted key length");
		return;
	}

	if (version && version != dpp->pkex_version) {
		l_debug("initiator is not using the same version, ignoring");
		return;
	}

	if (dpp->pkex_id) {
		if (!id || id_len != strlen(dpp->pkex_id) ||
				memcmp(dpp->pkex_id, id, id_len)) {
			l_debug("mismatch identifier, ignoring");
			return;
		}
	}

	m = l_ecc_point_from_data(dpp->curve, L_ECC_POINT_TYPE_FULL,
					key, key_len);
	if (!m) {
		l_debug("could not parse key from initiator, ignoring");
		return;
	}

	if (dpp->event_cb)
		dpp->event_cb(DPP_EVENT_PEER_ACCEPTED, NULL, dpp->user_data);

	if (!dpp->pkex_key) {
		/*
		 * "If an optional code identifier is used, it shall be a UTF-8
		 *  string not greater than eighty (80) octets"
		 */
		if (!id || id_len > 80 || !l_utf8_validate(id, id_len, NULL)) {
			l_debug("Configurator started with agent but enrollee "
				"sent invalid or no identifier, ignoring");
			return;
		}

		dpp->pkex_id = l_strndup(id, id_len);

		if (dpp->event_cb)
			dpp->event_cb(DPP_EVENT_PKEX_KEY_REQUESTED,
					dpp->pkex_id, dpp->user_data);

		/* Save the encrypted key/identifier for the agent callback */
		dpp->peer_encr_key = l_steal_ptr(m);

		return;
	}

	dpp_process_pkex_exchange_request(dpp, m);

	return;

bad_group:
	dpp_send_pkex_bad_group(dpp);
}

static void dpp_handle_pkex_commit_reveal_request(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const void *wrapped = NULL;
	size_t wrapped_len = 0;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	size_t unwrapped_len;
	uint8_t zero = 0;
	const void *key = 0;
	size_t key_len = 0;
	const void *i_auth = NULL;
	size_t i_auth_len = 0;
	_auto_(l_ecc_point_free) struct l_ecc_point *j = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *peer_public = NULL;
	uint8_t u[L_ECC_SCALAR_MAX_BYTES];
	size_t u_len = 0;
	uint8_t v[L_ECC_SCALAR_MAX_BYTES];
	size_t v_len = 0;

	l_debug("PKEX commit-reveal request");

	if (dpp->state != DPP_STATE_PKEX_COMMIT_REVEAL)
		return;

	if (dpp->role != DPP_CAPABILITY_CONFIGURATOR)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!wrapped) {
		l_debug("No wrapped data");
		return;
	}

	unwrapped = dpp_unwrap_attr(frame, 6, &zero, 1, dpp->z, dpp->z_len,
					wrapped, wrapped_len, &unwrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap attributes");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, unwrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_BOOTSTRAPPING_KEY:
			if (len != dpp->key_len * 2)
				return;

			key = data;
			key_len = len;
			break;
		case DPP_ATTR_INITIATOR_AUTH_TAG:
			if (len != 32)
				return;

			i_auth = data;
			i_auth_len = len;
			break;
		default:
			break;
		}
	}

	if (!key || !i_auth) {
		l_debug("missing attributes");
		return;
	}

	peer_public = l_ecc_point_from_data(dpp->curve,
					L_ECC_POINT_TYPE_FULL, key, key_len);
	if (!peer_public) {
		l_debug("peers boostrapping key did not validate");
		goto failed;
	}

	/* J' = y * A' */
	j = l_ecc_point_new(dpp->curve);

	l_ecc_point_multiply(j, dpp->pkex_private, peer_public);

	if (!dpp_derive_u(j, dpp->mac_initiator, peer_public,
			dpp->pkex_public, dpp->y_or_x, u, &u_len)) {
		l_debug("Failed to derive u");
		goto failed;
	}

	if (memcmp(u, i_auth, i_auth_len)) {
		l_debug("Initiator auth tag did not verify");
		goto failed;
	}

	/* L' = x * B' */
	l = l_ecc_point_new(dpp->curve);

	l_ecc_point_multiply(l, dpp->boot_private, dpp->y_or_x);

	if (!dpp_derive_v(l, dpp->mac_responder, dpp->boot_public, dpp->y_or_x,
				dpp->pkex_public, v, &v_len)) {
		l_debug("Failed to derive v");
		goto failed;
	}

	dpp_sm_set_peer_bootstrap(dpp, peer_public);

	dpp_send_pkex_commit_reveal_response(dpp, v, v_len);

	dpp->mutual_auth = true;
	dpp_start_authentication(dpp);

	return;

failed:
	dpp_failed(dpp);
}

static void dpp_handle_pkex_commit_reveal_response(struct dpp_sm *dpp,
					const uint8_t *frame, size_t frame_len)
{
	struct dpp_attr_iter iter;
	enum dpp_attribute_type type;
	size_t len;
	const uint8_t *data;
	const uint8_t *wrapped = NULL;
	size_t wrapped_len = 0;
	uint8_t one = 1;
	_auto_(l_free) uint8_t *unwrapped = NULL;
	size_t unwrapped_len = 0;
	const uint8_t *boot_key = NULL;
	size_t boot_key_len = 0;
	const uint8_t *r_auth = NULL;
	uint8_t v[L_ECC_SCALAR_MAX_BYTES];
	size_t v_len;
	_auto_(l_ecc_point_free) struct l_ecc_point *l = NULL;
	_auto_(l_ecc_point_free) struct l_ecc_point *peer_boot = NULL;

	l_debug("PKEX commit reveal response");

	if (dpp->state != DPP_STATE_PKEX_COMMIT_REVEAL)
		return;

	if (dpp->role != DPP_CAPABILITY_ENROLLEE)
		return;

	dpp_attr_iter_init(&iter, frame + 6, frame_len - 6);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_WRAPPED_DATA:
			wrapped = data;
			wrapped_len = len;
			break;
		default:
			break;
		}
	}

	if (!wrapped) {
		l_debug("No wrapped data");
		return;
	}

	unwrapped = dpp_unwrap_attr(frame, 6, &one, 1, dpp->z, dpp->z_len,
					wrapped, wrapped_len, &unwrapped_len);
	if (!unwrapped) {
		l_debug("Failed to unwrap Reveal-Commit message");
		return;
	}

	dpp_attr_iter_init(&iter, unwrapped, unwrapped_len);

	while (dpp_attr_iter_next(&iter, &type, &len, &data)) {
		switch (type) {
		case DPP_ATTR_BOOTSTRAPPING_KEY:
			if (len != dpp->key_len * 2)
				return;

			boot_key = data;
			boot_key_len = len;
			break;
		case DPP_ATTR_RESPONDER_AUTH_TAG:
			if (len != 32)
				return;

			r_auth = data;
			break;
		default:
			break;
		}
	}

	peer_boot = l_ecc_point_from_data(dpp->curve, L_ECC_POINT_TYPE_FULL,
							boot_key, boot_key_len);
	if (!peer_boot) {
		l_debug("Peer public bootstrapping key was invalid");
		goto failed;
	}

	/* L = b * X' */
	l = l_ecc_point_new(dpp->curve);

	l_ecc_point_multiply(l, dpp->pkex_private, peer_boot);

	if (!dpp_derive_v(l, dpp->mac_responder, peer_boot,
				dpp->pkex_public, dpp->y_or_x, v, &v_len)) {
		l_debug("Failed to derive v");
		goto failed;
	}

	if (memcmp(v, r_auth, v_len)) {
		l_debug("Bootstrapping data did not verify");
		goto failed;
	}

	dpp_sm_set_peer_bootstrap(dpp, peer_boot);

	dpp->mutual_auth = true;
	dpp_start_authentication(dpp);

	return;

failed:
	dpp_failed(dpp);
}

static bool dpp_validate_header(const uint8_t *data, size_t len,
					enum dpp_frame_type *type)
{
	/* Ensure header + message type */
	if (len < 6)
		return false;

	if (memcmp(data, wifi_alliance_oui, 3))
		return false;

	/* WiFi Allicance DPP OI type */
	if (data[3] != 0x1a)
		return false;

	/* Cryptosuite */
	if (data[4] != 1)
		return false;

	if (type)
		*type = data[5];

	return true;
}

static void dpp_handle_frame(struct dpp_sm *dpp,
				const uint8_t *data, size_t len)
{
	enum dpp_frame_type type;

	if (!dpp_validate_header(data, len, &type)) {
		l_debug("header did not validate");
		return;
	}

	switch (type) {
	case DPP_FRAME_AUTHENTICATION_REQUEST:
		dpp_handle_auth_request(dpp, data, len);
		break;
	case DPP_FRAME_AUTHENTICATION_RESPONSE:
		dpp_handle_auth_response(dpp, data, len);
		break;
	case DPP_FRAME_AUTHENTICATION_CONFIRM:
		dpp_handle_auth_confirm(dpp, data, len);
		break;
	case DPP_FRAME_CONFIGURATION_RESULT:
		dpp_handle_config_result_frame(dpp, data, len);
		break;
	case DPP_FRAME_PRESENCE_ANNOUNCEMENT:
		dpp_handle_presence_announcement(dpp, data, len);
		break;
	case DPP_FRAME_PKEX_XCHG_RESPONSE:
		dpp_handle_pkex_exchange_response(dpp, data, len);
		break;
	case DPP_FRAME_PKEX_COMMIT_REVEAL_RESPONSE:
		dpp_handle_pkex_commit_reveal_response(dpp, data, len);
		break;
	case DPP_FRAME_PKEX_VERSION1_XCHG_REQUEST:
		dpp_handle_pkex_v1_exchange_request(dpp, data, len);
		break;
	case DPP_FRAME_PKEX_COMMIT_REVEAL_REQUEST:
		dpp_handle_pkex_commit_reveal_request(dpp, data, len);
		break;
	default:
		l_debug("Unhandled DPP frame %u", type);
		break;
	}
}

void dpp_handle_rx(struct dpp_sm *dpp, const uint8_t *data, size_t len)
{
	if (len < 1)
		return;

	switch (*data) {
	case DPP_ACTION_VENDOR_SPECIFIC:
		dpp_handle_frame(dpp, data + 1, len - 1);
		break;
	/* For the GAS frames save the action byte to validate the frame */
	case DPP_ACTION_GAS_REQUEST:
		dpp_handle_config_request(dpp, data + 1, len - 1);
		break;
	case DPP_ACTION_GAS_RESPONSE:
		dpp_handle_config_response(dpp, data + 1, len - 1);
		break;
	default:
		break;
	}
}
