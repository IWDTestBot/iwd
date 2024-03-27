/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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

#define DPP_FRAME_MAX_RETRIES 5
#define DPP_FRAME_RETRY_TIMEOUT 1

static uint32_t netdev_watch;
static struct l_genl_family *nl80211;
static uint8_t broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static struct l_queue *dpp_list;
static uint32_t mlme_watch;
static uint32_t unicast_watch;

static uint8_t dpp_prefix[] = { 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01 };

enum dpp_interface {
	DPP_INTERFACE_UNBOUND,
	DPP_INTERFACE_DPP,
	DPP_INTERFACE_PKEX,
};

struct pkex_agent {
	char *owner;
	char *path;
	unsigned int disconnect_watch;
	uint32_t pending_id;
};

struct dpp {
	struct dpp_sm *sm;
	struct netdev *netdev;
	char *uri;
	uint8_t role;
	int refcount;
	uint32_t station_watch;
	uint32_t known_network_watch;

	uint64_t wdev_id;

	/* Could probably do away with storing these here */
	struct l_ecc_scalar *boot_private;
	struct l_ecc_point *boot_public;

	enum dpp_interface interface;

	struct pkex_agent *agent;

	/*
	 * List of frequencies to jump between. The presence of this list is
	 * also used to signify that a configurator is an initiator vs responder
	 */
	uint32_t *freqs;
	size_t freqs_len;
	size_t freqs_idx;
	uint32_t dwell;
	uint32_t current_freq;
	struct scan_freq_set *presence_list;
	uint32_t max_roc;

	uint32_t offchannel_id;

	uint8_t peer_addr[6];
	bool peer_accepted;

	/* Timeout of either auth/config protocol */
	struct l_timeout *timeout;

	uint32_t connect_scan_id;
	uint64_t frame_cookie;
	uint8_t frame_retry;
	void *frame_pending;
	size_t frame_size;
	struct l_timeout *retry_timeout;

	struct l_idle *connect_idle;

	uint32_t pkex_scan_id;

	bool mcast_support : 1;
	bool roc_started : 1;
};

static const char *dpp_role_to_string(enum dpp_capability role)
{
	switch (role) {
	case DPP_CAPABILITY_ENROLLEE:
		return "enrollee";
	case DPP_CAPABILITY_CONFIGURATOR:
		return "configurator";
	default:
		return NULL;
	}
}

static bool dpp_pkex_get_started(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp *dpp = user_data;
	bool started = (dpp->sm && dpp->interface == DPP_INTERFACE_PKEX);

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static bool dpp_pkex_get_role(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp *dpp = user_data;
	const char *role;

	if (!dpp->sm || dpp->interface != DPP_INTERFACE_PKEX)
		return false;

	role = dpp_role_to_string(dpp->role);
	if (L_WARN_ON(!role))
		return false;

	l_dbus_message_builder_append_basic(builder, 's', role);
	return true;
}

static bool dpp_get_started(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp *dpp = user_data;
	bool started = (dpp->sm && dpp->interface == DPP_INTERFACE_DPP);

	l_dbus_message_builder_append_basic(builder, 'b', &started);

	return true;
}

static bool dpp_get_role(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp *dpp = user_data;
	const char *role;

	if (!dpp->sm || dpp->interface != DPP_INTERFACE_DPP)
		return false;

	role = dpp_role_to_string(dpp->role);
	if (L_WARN_ON(!role))
		return false;

	l_dbus_message_builder_append_basic(builder, 's', role);
	return true;
}

static bool dpp_get_uri(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct dpp *dpp = user_data;

	if (!dpp->sm || dpp->interface != DPP_INTERFACE_DPP)
		return false;

	l_dbus_message_builder_append_basic(builder, 's', dpp->uri);
	return true;
}

static void dpp_property_changed_notify(struct dpp *dpp)
{
	const char *path = netdev_get_path(dpp->netdev);

	switch (dpp->interface) {
	case DPP_INTERFACE_DPP:
		l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
					"Started");
		l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
					"Role");
		l_dbus_property_changed(dbus_get_bus(), path, IWD_DPP_INTERFACE,
					"URI");
		break;
	case DPP_INTERFACE_PKEX:
		l_dbus_property_changed(dbus_get_bus(), path,
					IWD_DPP_PKEX_INTERFACE,
					"Started");
		l_dbus_property_changed(dbus_get_bus(), path,
					IWD_DPP_PKEX_INTERFACE,
					"Role");
		break;
	default:
		break;
	}
}

static void *dpp_serialize_iovec(struct iovec *iov, size_t iov_len,
				size_t *out_len)
{
	unsigned int i;
	size_t size = 0;
	uint8_t *ret;

	for (i = 0; i < iov_len; i++)
		size += iov[i].iov_len;

	ret = l_malloc(size);
	size = 0;

	for (i = 0; i < iov_len; i++) {
		memcpy(ret + size, iov[i].iov_base, iov[i].iov_len);
		size += iov[i].iov_len;
	}

	if (out_len)
		*out_len = size;

	return ret;
}

static void pkex_agent_free(void *data)
{
	struct pkex_agent *agent = data;

	l_free(agent->owner);
	l_free(agent->path);
	l_dbus_remove_watch(dbus_get_bus(), agent->disconnect_watch);
	l_free(agent);
}

static void dpp_agent_cancel(struct dpp *dpp)
{
	struct l_dbus_message *msg;

	const char *reason = "shutdown";

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						dpp->agent->owner,
						dpp->agent->path,
						IWD_SHARED_CODE_AGENT_INTERFACE,
						"Cancel");
	l_dbus_message_set_arguments(msg, "s", reason);
	l_dbus_message_set_no_reply(msg, true);
	l_dbus_send(dbus_get_bus(), msg);
}

static void dpp_agent_release(struct dpp *dpp)
{
	struct l_dbus_message *msg;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						dpp->agent->owner,
						dpp->agent->path,
						IWD_SHARED_CODE_AGENT_INTERFACE,
						"Release");
	l_dbus_message_set_arguments(msg, "");
	l_dbus_message_set_no_reply(msg, true);
	l_dbus_send(dbus_get_bus(), msg);
}

static void dpp_destroy_agent(struct dpp *dpp)
{
	if (!dpp->agent)
		return;

	if (dpp->agent->pending_id) {
		dpp_agent_cancel(dpp);
		l_dbus_cancel(dbus_get_bus(), dpp->agent->pending_id);
	}

	dpp_agent_release(dpp);

	l_debug("Released SharedCodeAgent on path %s", dpp->agent->path);

	pkex_agent_free(dpp->agent);
	dpp->agent = NULL;
}

static void dpp_reset(struct dpp *dpp)
{
	if (dpp->uri) {
		l_free(dpp->uri);
		dpp->uri = NULL;
	}

	if (dpp->freqs) {
		l_free(dpp->freqs);
		dpp->freqs = NULL;
	}

	if (dpp->offchannel_id) {
		offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);
		dpp->offchannel_id = 0;
	}

	if (dpp->timeout) {
		l_timeout_remove(dpp->timeout);
		dpp->timeout = NULL;
	}

	if (dpp->connect_scan_id) {
		scan_cancel(dpp->wdev_id, dpp->connect_scan_id);
		dpp->connect_scan_id = 0;
	}

	if (dpp->frame_pending) {
		l_free(dpp->frame_pending);
		dpp->frame_pending = NULL;
	}

	if (dpp->retry_timeout) {
		l_timeout_remove(dpp->retry_timeout);
		dpp->retry_timeout = NULL;
	}

	if (dpp->pkex_scan_id) {
		scan_cancel(dpp->wdev_id, dpp->pkex_scan_id);
		dpp->pkex_scan_id = 0;
	}

	if (dpp->connect_idle) {
		l_idle_remove(dpp->connect_idle);
		dpp->connect_idle = NULL;
	}

	dpp->frame_retry = 0;
	dpp->frame_cookie = 0;

	dpp_destroy_agent(dpp);

	dpp_property_changed_notify(dpp);

	dpp->interface = DPP_INTERFACE_UNBOUND;

	if (dpp->sm) {
		dpp_sm_free(dpp->sm);
		dpp->sm = NULL;
	}
}

static void dpp_free(struct dpp *dpp)
{
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));

	dpp_reset(dpp);

	if (dpp->boot_public) {
		l_ecc_point_free(dpp->boot_public);
		dpp->boot_public = NULL;
	}

	if (dpp->boot_private) {
		l_ecc_scalar_free(dpp->boot_private);
		dpp->boot_private = NULL;
	}

	/*
	 * Since this is called when the netdev goes down, station may already
	 * be gone in which case the state watch will automatically go away.
	 */
	if (station)
		station_remove_state_watch(station, dpp->station_watch);

	known_networks_watch_remove(dpp->known_network_watch);

	l_free(dpp);
}

static void dpp_send_frame_cb(struct l_genl_msg *msg, void *user_data)
{
	struct dpp *dpp = user_data;
	int err = l_genl_msg_get_error(msg);

	if (err < 0) {
		l_error("Error sending frame (%d)", err);
		return;
	}

	if (nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE, &dpp->frame_cookie,
				NL80211_ATTR_UNSPEC) < 0)
		l_error("Error parsing frame cookie");
}

static void dpp_send_frame(struct dpp *dpp,
				struct iovec *iov, size_t iov_len,
				uint32_t freq)
{
	struct l_genl_msg *msg;

	/*
	 * A received frame could potentially come in after the ROC session has
	 * ended. In this case the frame needs to be stored until ROC is started
	 * and sent at that time. The offchannel_id is also checked since
	 * this is not applicable when DPP is in a responder role waiting
	 * on the currently connected channel i.e. offchannel is never used.
	 */
	if (!dpp->roc_started && dpp->offchannel_id) {
		dpp->frame_pending = dpp_serialize_iovec(iov, iov_len,
							&dpp->frame_size);
		return;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 512);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dpp->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_OFFCHANNEL_TX_OK, 0, NULL);
	l_genl_msg_append_attrv(msg, NL80211_ATTR_FRAME, iov, iov_len);

	l_debug("Sending frame on frequency %u", freq);

	if (!l_genl_family_send(nl80211, msg, dpp_send_frame_cb, dpp, NULL)) {
		l_error("Could not send CMD_FRAME");
		l_genl_msg_unref(msg);
	}
}

static void dpp_frame_retry(struct dpp *dpp)
{
	struct iovec iov;

	iov.iov_base = dpp->frame_pending;
	iov.iov_len = dpp->frame_size;

	dpp_send_frame(dpp, &iov, 1, dpp->current_freq);

	l_free(dpp->frame_pending);
	dpp->frame_pending = NULL;
}

static size_t dpp_build_mpdu_header(const uint8_t *src,
					const uint8_t *dest, uint8_t *buf)
{
	struct mmpdu_header *hdr = (struct mmpdu_header *)buf;
	uint8_t *body;

	hdr->fc.protocol_version = 0;
	hdr->fc.type = MPDU_TYPE_MANAGEMENT;
	hdr->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_ACTION;
	memcpy(hdr->address_1, dest, 6);
	memcpy(hdr->address_2, src, 6);
	memcpy(hdr->address_3, broadcast, 6);

	body = buf + mmpdu_header_len(hdr);
	/* Category: Public */
	*body++ = 0x04;

	return body - buf;
}

static void dpp_write_config(const struct dpp_configuration *config,
				struct network *network)
{
	_auto_(l_settings_free) struct l_settings *settings = l_settings_new();
	_auto_(l_free) char *path;

	path = storage_get_network_file_path(SECURITY_PSK, config->ssid);

	if (l_settings_load_from_file(settings, path)) {
		/* Remove any existing Security keys */
		l_settings_remove_group(settings, "Security");
	}

	if (config->passphrase)
		l_settings_set_string(settings, "Security", "Passphrase",
				config->passphrase);
	else if (config->psk)
		l_settings_set_string(settings, "Security", "PreSharedKey",
				config->psk);

	if (config->send_hostname)
		l_settings_set_bool(settings, "IPv4", "SendHostname", true);

	if (config->hidden)
		l_settings_set_bool(settings, "Settings", "Hidden", true);

	l_debug("Storing credential for '%s(%s)'", config->ssid,
						security_to_str(SECURITY_PSK));
	storage_network_sync(SECURITY_PSK, config->ssid, settings);
}

static void dpp_scan_triggered(int err, void *user_data)
{
	/* Not much can be done in this case */
	if (err < 0)
		l_error("Failed to trigger DPP scan");
}

static void dpp_start_connect(struct l_idle *idle, void *user_data)
{
	struct dpp *dpp = user_data;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct scan_bss *bss;
	struct network *network;
	int ret;
	const struct dpp_configuration *config;

	config = dpp_sm_get_configuration(dpp->sm);
	if (L_WARN_ON(!config))
		return;

	network = station_network_find(station, config->ssid, SECURITY_PSK);

	dpp_reset(dpp);

	if (!network) {
		l_debug("Network was not found!");
		return;
	}

	l_debug("connecting to %s from DPP", network_get_ssid(network));

	bss = network_bss_select(network, true);
	ret = network_autoconnect(network, bss);
	if (ret < 0)
		l_warn("failed to connect after DPP (%d) %s", ret,
			strerror(-ret));
}

static bool dpp_scan_results(int err, struct l_queue *bss_list,
				const struct scan_freq_set *freqs,
				void *userdata)
{
	struct dpp *dpp = userdata;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));

	if (err < 0)
		goto reset;

	if (!bss_list || l_queue_length(bss_list) == 0)
		goto reset;

	/*
	 * The station watch _should_ detect this and reset, which cancels the
	 * scan. But just in case...
	 */
	if (L_WARN_ON(station_get_connected_network(station)))
		goto reset;

	station_set_scan_results(station, bss_list, freqs, false);

	dpp_start_connect(NULL, dpp);

	return true;

reset:
	return false;
}

static void dpp_scan_destroy(void *userdata)
{
	struct dpp *dpp = userdata;

	dpp->connect_scan_id = 0;
	dpp_reset(dpp);
}

static void dpp_known_network_watch(enum known_networks_event event,
					const struct network_info *info,
					void *user_data)
{
	struct dpp *dpp = user_data;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	const struct dpp_configuration *config;
	/*
	 * Check the following
	 *  - DPP is enrolling
	 *  - DPP finished (dpp->config is set)
	 *  - This is for the network DPP just configured
	 *  - DPP isn't already trying to connect (e.g. if the profile was
	 *    immediately modified after DPP synced it).
	 *  - DPP didn't start a scan for the network.
	 */
	if (!dpp->sm)
		return;

	config = dpp_sm_get_configuration(dpp->sm);

	if (dpp->role != DPP_CAPABILITY_ENROLLEE)
		return;
	if (!config)
		return;
	if (strcmp(info->ssid, config->ssid))
		return;
	if (dpp->connect_idle)
		return;
	if (dpp->connect_scan_id)
		return;
	if (!station || station_get_connected_network(station))
		return;

	switch (event) {
	case KNOWN_NETWORKS_EVENT_ADDED:
	case KNOWN_NETWORKS_EVENT_UPDATED:
		/*
		 * network.c takes care of updating the settings for the
		 * network. This callback just tells us to begin the connection.
		 * We do have use an idle here because there is no strict
		 * guarantee of ordering between known network events, e.g. DPP
		 * could have been called into prior to network and the network
		 * object isn't updated yet.
		 */
		dpp->connect_idle = l_idle_create(dpp_start_connect, dpp, NULL);
		break;
	case KNOWN_NETWORKS_EVENT_REMOVED:
		l_warn("profile was removed before DPP could connect");
		break;
	}
}

static void dpp_handle_config_frame(const struct mmpdu_header *frame,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct dpp *dpp = user_data;

	if (!dpp->sm)
		return;

	dpp_handle_rx(dpp->sm, body + 1, body_len - 1);
}

static void dpp_tx_frame(const uint8_t *data, size_t len,
				void *user_data)
{
	struct dpp *dpp = user_data;
	struct iovec iov[2];
	uint8_t hdr[36];

	memset(hdr, 0, sizeof(hdr));

	iov[0].iov_len = dpp_build_mpdu_header(netdev_get_address(dpp->netdev),
						dpp->peer_addr, hdr);
	iov[0].iov_base = hdr;

	iov[1].iov_base = (void *)data;
	iov[1].iov_len = len;

	dpp_send_frame(dpp, iov, 2, dpp->current_freq);
}

static void dpp_roc_started(void *user_data)
{
	struct dpp *dpp = user_data;

	dpp->roc_started = true;

	dpp_sm_set_write_handler(dpp->sm, dpp_tx_frame);

	/*
	 * The retry timer indicates a frame was not acked in which case we
	 * should not change any state or send any frames until that expires.
	 */
	if (dpp->retry_timeout)
		return;

	if (dpp->frame_pending) {
		dpp_frame_retry(dpp);
		return;
	}
}

static void dpp_start_offchannel(struct dpp *dpp, uint32_t freq);

static void dpp_offchannel_timeout(int error, void *user_data)
{
	struct dpp *dpp = user_data;

	dpp->offchannel_id = 0;
	dpp->roc_started = false;

	dpp_sm_set_write_handler(dpp->sm, NULL);

	/*
	 * If cancelled this is likely due to netdev going down or from Stop().
	 * Otherwise there was some other problem which is probably not
	 * recoverable.
	 */
	if (error == -ECANCELED)
		return;
	else if (error == -EIO)
		goto next_roc;
	else if (error < 0)
		goto protocol_failed;

	dpp->freqs_idx++;

	if (dpp->freqs_idx >= dpp->freqs_len) {
		l_debug("Max retries offchannel");
		dpp->freqs_idx = 0;
	}

	dpp->current_freq = dpp->freqs[dpp->freqs_idx];

	l_debug("Offchannel timeout, moving to next frequency %u, duration %u",
			dpp->current_freq, dpp->dwell);

next_roc:
	dpp_start_offchannel(dpp, dpp->current_freq);

	return;

protocol_failed:
	dpp_reset(dpp);
}

static void dpp_start_offchannel(struct dpp *dpp, uint32_t freq)
{
	/*
	 * This needs to be handled carefully for a few reasons:
	 *
	 * First, the next offchannel operation needs to be started prior to
	 * canceling an existing one. This is so the offchannel work can
	 * continue uninterrupted without any other work items starting in
	 * between canceling and starting the next (e.g. if a scan request is
	 * sitting in the queue).
	 *
	 * Second, dpp_offchannel_timeout resets dpp->offchannel_id to zero
	 * which is why the new ID is saved and only set to dpp->offchannel_id
	 * once the previous offchannel work is cancelled (i.e. destroy() has
	 * been called).
	 */
	uint32_t id = offchannel_start(netdev_get_wdev_id(dpp->netdev),
				WIPHY_WORK_PRIORITY_OFFCHANNEL,
				freq, dpp->dwell, dpp_roc_started,
				dpp, dpp_offchannel_timeout);

	if (dpp->offchannel_id)
		offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);

	l_debug("starting offchannel on frequency %u, dwell=%u", freq, dpp->dwell);

	dpp->offchannel_id = id;
}

static void dpp_handle_frame(struct dpp *dpp,
				const struct mmpdu_header *frame,
				const void *body, size_t body_len)
{
	if (!dpp->sm)
		return;

	/* Frame from a different device after DPP has already started */
	if (dpp->peer_accepted && memcmp(dpp->peer_addr, frame->address_2, 6))
		return;

	memcpy(dpp->peer_addr, frame->address_2, 6);

	dpp_handle_rx(dpp->sm, body + 1, body_len - 1);
}

static bool match_wdev(const void *a, const void *b)
{
	const struct dpp *dpp = a;
	const uint64_t *wdev_id = b;

	return *wdev_id == dpp->wdev_id;
}

static void dpp_frame_timeout(struct l_timeout *timeout, void *user_data)
{
	struct dpp *dpp = user_data;

	l_timeout_remove(timeout);
	dpp->retry_timeout = NULL;

	/*
	 * ROC has not yet started (in between an ROC timeout and starting a
	 * new session), this will most likely result in the frame failing to
	 * send. Just bail out now and the roc_started callback will take care
	 * of sending this out.
	 */
	if (dpp->offchannel_id && !dpp->roc_started)
		return;

	dpp_frame_retry(dpp);
}

static void dpp_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct dpp *dpp;
	uint64_t wdev_id = 0;
	uint64_t cookie = 0;
	bool ack = false;
	struct iovec iov;
	uint8_t cmd = l_genl_msg_get_command(msg);
	enum dpp_state state;

	if (cmd != NL80211_CMD_FRAME_TX_STATUS)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
				NL80211_ATTR_COOKIE, &cookie,
				NL80211_ATTR_ACK, &ack,
				NL80211_ATTR_FRAME, &iov,
				NL80211_ATTR_UNSPEC) < 0)
		return;

	dpp = l_queue_find(dpp_list, match_wdev, &wdev_id);
	if (!dpp || !dpp->sm)
		return;

	state = dpp_sm_get_state(dpp->sm);

	/*
	 * Don't retransmit for presence or PKEX exchange if an enrollee, both
	 * are broadcast frames which don't expect an ack.
	 */
	if (state == DPP_STATE_PRESENCE ||
			(state == DPP_STATE_PKEX_EXCHANGE &&
			dpp->role == DPP_CAPABILITY_ENROLLEE))
		return;

	if (dpp->frame_cookie != cookie)
		return;

	/*
	 * Only want to handle the no-ACK case. Re-transmitting an ACKed
	 * frame likely wont do any good, at least in the case of DPP.
	 */
	if (!ack)
		goto retransmit;

	return;

retransmit:
	if (dpp->frame_retry > DPP_FRAME_MAX_RETRIES) {
		dpp_reset(dpp);
		return;
	}

	/* This should never happen */
	if (L_WARN_ON(dpp->frame_pending))
		return;

	l_debug("No ACK from peer, re-transmitting in %us",
			DPP_FRAME_RETRY_TIMEOUT);

	dpp->frame_retry++;

	dpp->frame_pending = l_memdup(iov.iov_base, iov.iov_len);
	dpp->frame_size = iov.iov_len;
	dpp->retry_timeout = l_timeout_create(DPP_FRAME_RETRY_TIMEOUT,
						dpp_frame_timeout, dpp, NULL);
}

static void dpp_unicast_notify(struct l_genl_msg *msg, void *user_data)
{
	struct dpp *dpp;
	const uint64_t *wdev_id = NULL;
	struct l_genl_attr attr;
	uint16_t type, len, frame_len;
	const void *data;
	const struct mmpdu_header *mpdu = NULL;
	const uint8_t *body;
	size_t body_len;

	if (l_genl_msg_get_command(msg) != NL80211_CMD_FRAME)
		return;

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case NL80211_ATTR_WDEV:
			if (len != 8)
				break;

			wdev_id = data;
			break;

		case NL80211_ATTR_FRAME:
			mpdu = mpdu_validate(data, len);
			if (!mpdu) {
				l_warn("Frame didn't validate as MMPDU");
				return;
			}

			frame_len = len;
			break;
		}
	}

	if (!wdev_id) {
		l_warn("Bad wdev attribute");
		return;
	}

	dpp = l_queue_find(dpp_list, match_wdev, wdev_id);
	if (!dpp)
		return;

	if (!mpdu) {
		l_warn("Missing frame data");
		return;
	}

	body = mmpdu_body(mpdu);
	body_len = (const uint8_t *) mpdu + frame_len - body;

	if (body_len < sizeof(dpp_prefix) ||
			memcmp(body, dpp_prefix, sizeof(dpp_prefix)) != 0)
		return;

	dpp_handle_frame(dpp, mpdu, body, body_len);
}

static void dpp_frame_watch_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("Could not register frame watch type %04x: %i",
			L_PTR_TO_UINT(user_data), l_genl_msg_get_error(msg));
}

/*
 * Special case the frame watch which includes the presence frames since they
 * require multicast support. This is only supported by ath9k, so adding
 * general support to frame-xchg isn't desireable.
 */
static void dpp_frame_watch(struct dpp *dpp, uint16_t frame_type,
				const uint8_t *prefix, size_t prefix_len)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new_sized(NL80211_CMD_REGISTER_FRAME, 32 + prefix_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &dpp->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_TYPE, 2, &frame_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME_MATCH,
				prefix_len, prefix);
	if (dpp->mcast_support)
		l_genl_msg_append_attr(msg, NL80211_ATTR_RECEIVE_MULTICAST,
					0, NULL);

	l_genl_family_send(nl80211, msg, dpp_frame_watch_cb,
					L_UINT_TO_PTR(frame_type), NULL);
}

/*
 * Station is unaware of DPP's state so we need to handle a few cases here so
 * weird stuff doesn't happen:
 *
 *   - While configuring we should stay connected, a disconnection/roam should
 *     stop DPP since it would fail regardless due to the hardware going idle
 *     or changing channels since configurators assume all comms will be
 *     on-channel.
 *   - While enrolling we should stay disconnected. If station connects during
 *     enrolling it would cause 2x calls to __station_connect_network after
 *     DPP finishes.
 *
 * Other conditions shouldn't ever happen i.e. configuring and going into a
 * connecting state or enrolling and going to a disconnected/roaming state.
 */
static void dpp_station_state_watch(enum station_state state, void *user_data)
{
	struct dpp *dpp = user_data;

	if (!dpp->sm)
		return;

	switch (state) {
	case STATION_STATE_DISCONNECTED:
	case STATION_STATE_DISCONNECTING:
	case STATION_STATE_ROAMING:
	case STATION_STATE_FT_ROAMING:
	case STATION_STATE_FW_ROAMING:
		if (L_WARN_ON(dpp->role == DPP_CAPABILITY_ENROLLEE))
			dpp_reset(dpp);

		if (dpp->role == DPP_CAPABILITY_CONFIGURATOR) {
			l_debug("Disconnected while configuring, stopping DPP");
			dpp_reset(dpp);
		}

		break;
	case STATION_STATE_CONNECTING:
	case STATION_STATE_CONNECTED:
	case STATION_STATE_CONNECTING_AUTO:
	case STATION_STATE_NETCONFIG:
		if (L_WARN_ON(dpp->role == DPP_CAPABILITY_CONFIGURATOR))
			dpp_reset(dpp);

		if (dpp->role == DPP_CAPABILITY_ENROLLEE) {
			l_debug("Connecting while enrolling, stopping DPP");
			dpp_reset(dpp);
		}

		break;

	/*
	 * Autoconnect states are fine for enrollees. This makes it nicer for
	 * the user since they don't need to explicity Disconnect() to disable
	 * autoconnect, then re-enable it if DPP fails.
	 */
	case STATION_STATE_AUTOCONNECT_FULL:
	case STATION_STATE_AUTOCONNECT_QUICK:
		if (L_WARN_ON(dpp->role == DPP_CAPABILITY_CONFIGURATOR))
			dpp_reset(dpp);

		break;
	}
}

static void dpp_create(struct netdev *netdev)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct dpp *dpp = l_new(struct dpp, 1);
	uint8_t dpp_conf_response_prefix[] = { 0x04, 0x0b };
	uint8_t dpp_conf_request_prefix[] = { 0x04, 0x0a };
	uint64_t wdev_id = netdev_get_wdev_id(netdev);
	struct station *station = station_find(netdev_get_ifindex(netdev));
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(19);

	dpp->netdev = netdev;
	dpp->interface = DPP_INTERFACE_UNBOUND;
	dpp->wdev_id = wdev_id;
	dpp->max_roc = wiphy_get_max_roc_duration(wiphy_find_by_wdev(wdev_id));
	dpp->mcast_support = wiphy_has_ext_feature(
				wiphy_find_by_wdev(dpp->wdev_id),
				NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS);

	/* TODO: Support a user-provided key pair */
	l_ecdh_generate_key_pair(curve, &dpp->boot_private,
					&dpp->boot_public);

	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_DPP_INTERFACE, dpp);
	l_dbus_object_add_interface(dbus, netdev_get_path(netdev),
					IWD_DPP_PKEX_INTERFACE, dpp);
	/*
	 * Since both interfaces share the dpp set this to 2. Currently both
	 * interfaces are added/removed in unison so we _could_ simply omit the
	 * destroy callback on one of them. But for consistency and future
	 * proofing use a reference count and the final interface being removed
	 * will destroy the dpp.
	 */
	dpp->refcount = 2;

	dpp_frame_watch(dpp, 0x00d0, dpp_prefix, sizeof(dpp_prefix));

	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_response_prefix,
				sizeof(dpp_conf_response_prefix),
				dpp_handle_config_frame, dpp, NULL);
	frame_watch_add(netdev_get_wdev_id(netdev), 0, 0x00d0,
				dpp_conf_request_prefix,
				sizeof(dpp_conf_request_prefix),
				dpp_handle_config_frame, dpp, NULL);

	dpp->station_watch = station_add_state_watch(station,
					dpp_station_state_watch, dpp, NULL);
	dpp->known_network_watch = known_networks_watch_add(
					dpp_known_network_watch, dpp, NULL);

	l_queue_push_tail(dpp_list, dpp);
}

static void dpp_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_NEW:
	case NETDEV_WATCH_EVENT_UP:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			dpp_create(netdev);
		break;
	case NETDEV_WATCH_EVENT_DEL:
	case NETDEV_WATCH_EVENT_DOWN:
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(netdev),
						IWD_DPP_INTERFACE);
		l_dbus_object_remove_interface(dbus_get_bus(),
						netdev_get_path(netdev),
						IWD_DPP_PKEX_INTERFACE);
		break;
	default:
		break;
	}
}

/*
 * EasyConnect 2.0 - 6.2.2
 */
static uint32_t *dpp_add_default_channels(struct dpp *dpp, size_t *len_out)
{
	struct wiphy *wiphy = wiphy_find_by_wdev(
					netdev_get_wdev_id(dpp->netdev));
	const struct scan_freq_set *list = wiphy_get_supported_freqs(wiphy);
	uint32_t freq;

	if (!dpp->presence_list)
		dpp->presence_list = scan_freq_set_new();

	scan_freq_set_add(dpp->presence_list, band_channel_to_freq(6,
						BAND_FREQ_2_4_GHZ));
	/*
	 * "5 GHz: Channel 44 (5.220 GHz) if local regulations permit operation
	 * only in the 5.150 - 5.250 GHz band and Channel 149 (5.745 GHz)
	 * otherwise"
	 */
	freq = band_channel_to_freq(149, BAND_FREQ_5_GHZ);

	if (scan_freq_set_contains(list, freq))
		scan_freq_set_add(dpp->presence_list, freq);
	else
		scan_freq_set_add(dpp->presence_list,
				band_channel_to_freq(44, BAND_FREQ_5_GHZ));

	/* TODO: 60GHz: Channel 2 */

	return scan_freq_set_to_fixed_array(dpp->presence_list, len_out);
}

/*
 * TODO: There is an entire procedure defined in the spec where you increase
 * the ROC timeout with each unsuccessful iteration of channels, wait on channel
 * for long periods of time etc. Due to offchannel issues in the kernel this
 * procedure is not being fully implemented. In reality doing this would result
 * in quite terrible DPP performance anyways.
 */
static void dpp_start_presence(struct dpp *dpp, uint32_t *limit_freqs,
					size_t limit_len)
{
	if (limit_freqs) {
		dpp->freqs = l_memdup(limit_freqs, sizeof(uint32_t) * limit_len);
		dpp->freqs_len = limit_len;
	} else
		dpp->freqs = dpp_add_default_channels(dpp, &dpp->freqs_len);

	dpp->dwell = (dpp->max_roc < 2000) ? dpp->max_roc : 2000;
	dpp->freqs_idx = 0;
	dpp->current_freq = dpp->freqs[0];

	dpp_start_offchannel(dpp, dpp->current_freq);
}

static void dpp_event_success(struct dpp *dpp)
{
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct network *network = NULL;
	struct scan_bss *bss = NULL;
	const struct dpp_configuration *config;

	config = dpp_sm_get_configuration(dpp->sm);
	if (L_WARN_ON(!config))
		goto reset;

	/*
	 * We should have a station device, but if not DPP can write the
	 * credentials out and be done
	 */
	if (station) {
		network = station_network_find(station, config->ssid,
						SECURITY_PSK);
		if (network)
			bss = network_bss_select(network, true);
	}

	dpp_write_config(config, network);

	offchannel_cancel(dpp->wdev_id, dpp->offchannel_id);
	dpp->offchannel_id = 0;

	if (network && bss) {
		l_debug("delaying connect until settings are synced");
		return;
	} else if (station) {
		struct scan_parameters params = {0};

		params.ssid = (void *) config->ssid;
		params.ssid_len = config->ssid_len;

		l_debug("Scanning for %s", config->ssid);

		dpp->connect_scan_id = scan_active_full(dpp->wdev_id, &params,
						dpp_scan_triggered,
						dpp_scan_results, dpp,
						dpp_scan_destroy);
		if (dpp->connect_scan_id)
			return;
	}

reset:
	dpp_reset(dpp);
}

static void dpp_event_channel_switch(struct dpp *dpp,
					const uint8_t *attr)
{
	uint32_t freq;

	freq = oci_to_frequency(attr[0], attr[1]);

	if (freq == dpp->current_freq)
		return;

	dpp->current_freq = freq;

	dpp_start_offchannel(dpp, dpp->current_freq);

	/*
	 * The common code will attempt to write after this, so ensure that
	 * gets delayed until we are on the right channel
	 */
	dpp_sm_set_write_handler(dpp->sm, NULL);
}

static void dpp_pkex_agent_reply(struct l_dbus_message *message,
					void *user_data)
{
	struct dpp *dpp = user_data;
	const char *error, *text;
	const char *code;

	dpp->agent->pending_id = 0;

	l_debug("SharedCodeAgent %s path %s replied", dpp->agent->owner,
			dpp->agent->path);

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("RequestSharedCode() returned %s(\"%s\")",
				error, text);
		return;
	}

	if (!l_dbus_message_get_arguments(message, "s", &code)) {
		l_debug("Invalid arguments, check SharedCodeAgent!");
		return;
	}

	dpp_sm_set_pkex_key(dpp->sm, code);
}

static bool dpp_event_pkex_key_requested(struct dpp *dpp,
					const char *identifier)
{
	struct l_dbus_message *msg;

	if (!dpp->agent)
		return false;

	if (L_WARN_ON(dpp->agent->pending_id))
		return false;

	msg = l_dbus_message_new_method_call(dbus_get_bus(),
						dpp->agent->owner,
						dpp->agent->path,
						IWD_SHARED_CODE_AGENT_INTERFACE,
						"RequestSharedCode");
	l_dbus_message_set_arguments(msg, "s", identifier);

	dpp->agent->pending_id = l_dbus_send_with_reply(dbus_get_bus(),
							msg,
							dpp_pkex_agent_reply,
							dpp, NULL);
	return dpp->agent->pending_id != 0;
}

static void dpp_event_peer_accepted(struct dpp *dpp)
{
	dpp->peer_accepted = true;

	if (dpp_sm_get_state(dpp->sm) != DPP_STATE_PKEX_EXCHANGE)
		return;

	dpp_sm_set_pkex_peer_mac(dpp->sm, dpp->peer_addr);

	/*
	 * PKEX dictates a 200ms timeout waiting for the exchange
	 * response. After this there is no time requirement for the
	 * remainder of the protocol. Increase the dwell time so we
	 * have the best chance of receiving frames since we will now
	 * remain on a single frequency.
	 */
	if (dpp->role == DPP_CAPABILITY_ENROLLEE)
		dpp->dwell = (dpp->max_roc < 2000) ? dpp->max_roc : 2000;
}

static void dpp_event(enum dpp_event event, const void *event_data,
			void *user_data)
{
	struct dpp *dpp = user_data;

	switch (event) {
	case DPP_EVENT_PEER_ACCEPTED:
		dpp_event_peer_accepted(dpp);
		break;
	case DPP_EVENT_CHANNEL_SWITCH:
		dpp_event_channel_switch(dpp, event_data);
		break;
	case DPP_EVENT_PKEX_KEY_REQUESTED:
		dpp_event_pkex_key_requested(dpp, event_data);
		break;
	case DPP_EVENT_FAILED:
		dpp_reset(dpp);
		break;
	case DPP_EVENT_SUCCESS:
		if (dpp->role == DPP_CAPABILITY_ENROLLEE)
			dpp_event_success(dpp);
		else
			dpp_reset(dpp);
		break;
	}
}

static struct l_dbus_message *dpp_dbus_start_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp *dpp = user_data;
	uint32_t freq = band_channel_to_freq(6, BAND_FREQ_2_4_GHZ);
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct l_dbus_message *reply;
	const uint8_t *own_asn1;
	size_t own_asn1_len;

	if (dpp->sm || dpp->interface != DPP_INTERFACE_UNBOUND)
		return dbus_error_busy(message);

	/*
	 * Station isn't actually required for DPP itself, although this will
	 * prevent connecting to the network once configured.
	 */
	if (station && station_get_connected_network(station)) {
		l_warn("cannot be enrollee while connected, please disconnect");
		return dbus_error_busy(message);
	} else if (!station)
		l_debug("No station device, continuing anyways...");

	dpp->sm = dpp_sm_new(dpp_event, dpp->boot_public,
				dpp->boot_private, dpp);

	dpp_sm_set_role(dpp->sm, DPP_CAPABILITY_ENROLLEE);
	dpp_sm_start_responder(dpp->sm);

	own_asn1 = dpp_sm_get_own_asn1(dpp->sm, &own_asn1_len);

	dpp->uri = dpp_generate_uri(own_asn1, own_asn1_len, 2,
					netdev_get_address(dpp->netdev), &freq,
					1, NULL, NULL);

	dpp->role = DPP_CAPABILITY_ENROLLEE;
	dpp->interface = DPP_INTERFACE_DPP;

	l_debug("DPP Start Enrollee: %s", dpp->uri);

	/*
	 * Going off spec here. Select a single channel to send presence
	 * announcements on. This will be advertised in the URI. The full
	 * presence procedure can be implemented if it is ever needed.
	 */
	dpp_start_presence(dpp, &freq, 1);

	dpp_property_changed_notify(dpp);

	memcpy(dpp->peer_addr, broadcast, 6);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "s", dpp->uri);

	return reply;
}

/*
 * Set up the configurator for an initiator role. The configurator
 * will go offchannel to frequencies advertised by the enrollees URI or,
 * if no channels are provided, use a default channel list.
 */
static bool dpp_configurator_start_presence(struct dpp *dpp, const char *uri)
{
	_auto_(l_free) uint32_t *freqs = NULL;
	size_t freqs_len = 0;
	struct dpp_uri_info *info;

	info = dpp_parse_uri(uri);
	if (!info)
		return false;

	/*
	 * Very few drivers actually support registration of multicast frames.
	 * This renders the presence procedure impossible on most drivers.
	 * But not all is lost. If the URI contains the MAC and channel
	 * info we an start going through channels sending auth requests which
	 * is basically DPP 1.0. Otherwise DPP cannot start.
	 */
	if (!dpp->mcast_support &&
				(l_memeqzero(info->mac, 6) || !info->freqs)) {
		l_error("No multicast registration support, URI must contain "
			"MAC and channel information");
		dpp_free_uri_info(info);
		return false;
	}

	if (!l_memeqzero(info->mac, 6)) {
		memcpy(dpp->peer_addr, info->mac, 6);
		/* Set now so we restrict to only frames from this MAC */
		dpp->peer_accepted = true;
	}

	if (info->freqs)
		freqs = scan_freq_set_to_fixed_array(info->freqs, &freqs_len);

	dpp_sm_set_peer_bootstrap(dpp->sm, info->boot_public);
	dpp_free_uri_info(info);

	dpp_start_presence(dpp, freqs, freqs_len);

	return true;
}

static struct l_dbus_message *dpp_start_configurator_common(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data,
						bool responder)
{
	struct dpp *dpp = user_data;
	struct l_dbus_message *reply;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct scan_bss *bss;
	struct network *network;
	struct l_settings *settings;
	struct handshake_state *hs = netdev_get_handshake(dpp->netdev);
	const char *uri;
	struct dpp_configuration *config;
	const uint8_t *own_asn1;
	size_t own_asn1_len;

	/*
	 * For now limit the configurator to only configuring enrollees to the
	 * currently connected network.
	 */
	if (!station)
		return dbus_error_not_available(message);

	bss = station_get_connected_bss(station);
	network = station_get_connected_network(station);
	if (!bss || !network)
		return dbus_error_not_connected(message);

	settings = network_get_settings(network);
	if (!settings)
		return dbus_error_not_configured(message);

	if (network_get_security(network) != SECURITY_PSK)
		return dbus_error_not_supported(message);

	if (dpp->sm || dpp->interface != DPP_INTERFACE_UNBOUND)
		return dbus_error_busy(message);

	dpp->sm = dpp_sm_new(dpp_event, dpp->boot_public,
				dpp->boot_private, dpp);

	if (!responder) {
		if (!l_dbus_message_get_arguments(message, "s", &uri))
			return dbus_error_invalid_args(message);

		if (!dpp_configurator_start_presence(dpp, uri))
			return dbus_error_invalid_args(message);

		if (!dpp->mcast_support)
			dpp_sm_set_skip_presence(dpp->sm, true);
	} else
		dpp->current_freq = bss->frequency;

	config = dpp_configuration_new(settings, network_get_ssid(network),
						hs->akm_suite);

	dpp_sm_set_configuration(dpp->sm, config);
	dpp_sm_set_role(dpp->sm, DPP_CAPABILITY_CONFIGURATOR);

	own_asn1 = dpp_sm_get_own_asn1(dpp->sm, &own_asn1_len);

	dpp->uri = dpp_generate_uri(own_asn1, own_asn1_len, 2,
					netdev_get_address(dpp->netdev),
					&bss->frequency, 1, NULL, NULL);
	dpp->interface = DPP_INTERFACE_DPP;

	dpp->dwell = (dpp->max_roc < 2000) ? dpp->max_roc : 2000;

	dpp_property_changed_notify(dpp);

	dpp->role = DPP_CAPABILITY_CONFIGURATOR;

	memcpy(dpp->peer_addr, broadcast, 6);

	l_debug("DPP Start Configurator: %s", dpp->uri);

	reply = l_dbus_message_new_method_return(message);

	l_dbus_message_set_arguments(reply, "s", dpp->uri);

	/*
	 * Configurators acting as responders are always on channel so
	 * the writes can be done at any point.
	 */
	if (responder) {
		dpp_sm_set_write_handler(dpp->sm, dpp_tx_frame);
		dpp_sm_start_responder(dpp->sm);
	} else
		dpp_sm_start_initiator(dpp->sm);

	return reply;
}

static struct l_dbus_message *dpp_dbus_start_configurator(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dpp_start_configurator_common(dbus, message, user_data, true);
}

static struct l_dbus_message *dpp_dbus_configure_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	return dpp_start_configurator_common(dbus, message, user_data, false);
}

static struct l_dbus_message *dpp_dbus_stop(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp *dpp = user_data;

	l_debug("");

	if (dpp->interface != DPP_INTERFACE_DPP)
		return dbus_error_not_found(message);

	dpp_reset(dpp);

	return l_dbus_message_new_method_return(message);
}

static void dpp_pkex_scan_trigger(int err, void *user_data)
{
	struct dpp *dpp = user_data;

	if (err < 0)
		dpp_reset(dpp);
}

/*
 * Section 5.6.1
 * In lieu of specific channel information obtained in a manner outside
 * the scope of this specification, PKEX responders shall select one of
 * the following channels:
 *  - 2.4 GHz: Channel 6 (2.437 GHz)
 *  - 5 GHz: Channel 44 (5.220 GHz) if local regulations permit
 *           operation only in the 5.150 - 5.250 GHz band and Channel
 *           149 (5.745 GHz) otherwise
 */
static uint32_t *dpp_default_freqs(struct dpp *dpp, size_t *out_len)
{
	struct wiphy *wiphy = wiphy_find_by_wdev(dpp->wdev_id);
	uint32_t default_channels[3] = { 2437, 5220, 5745 };
	uint32_t *freqs_out;
	size_t len = 0;

	if ((wiphy_get_supported_bands(wiphy) & BAND_FREQ_2_4_GHZ) &&
			scan_get_band_rank_modifier(BAND_FREQ_2_4_GHZ) != 0)
		default_channels[len++] = 2437;

	if ((wiphy_get_supported_bands(wiphy) & BAND_FREQ_5_GHZ) &&
			scan_get_band_rank_modifier(BAND_FREQ_5_GHZ) != 0) {
		default_channels[len++] = 5220;
		default_channels[len++] = 5745;
	}

	if (!len) {
		l_warn("No bands are allowed, check BandModifier* settings!");
		return NULL;
	}

	freqs_out = l_memdup(default_channels, sizeof(uint32_t) * len);
	*out_len = len;

	return freqs_out;
}

static bool dpp_pkex_scan_notify(int err, struct l_queue *bss_list,
					const struct scan_freq_set *freqs,
					void *user_data)
{
	struct dpp *dpp = user_data;
	const struct l_queue_entry *e;
	_auto_(scan_freq_set_free) struct scan_freq_set *freq_set = NULL;

	if (err < 0)
		goto failed;

	freq_set = scan_freq_set_new();

	if (!bss_list || l_queue_isempty(bss_list)) {
		dpp->freqs = dpp_default_freqs(dpp, &dpp->freqs_len);
		if (!dpp->freqs)
			goto failed;

		l_debug("No BSS's seen, using default frequency list");
		goto start;
	}

	for (e = l_queue_get_entries(bss_list); e; e = e->next) {
		const struct scan_bss *bss = e->data;

		scan_freq_set_add(freq_set, bss->frequency);
	}

	l_debug("Found %u frequencies to search for configurator",
			l_queue_length(bss_list));

	dpp->freqs = scan_freq_set_to_fixed_array(freq_set, &dpp->freqs_len);

start:
	dpp->current_freq = dpp->freqs[0];

	l_debug("PKEX start enrollee");

	dpp_start_offchannel(dpp, dpp->current_freq);

	dpp_sm_pkex_start_initiator(dpp->sm);

	return false;

failed:
	dpp_reset(dpp);
	return false;
}

static void dpp_pkex_scan_destroy(void *user_data)
{
	struct dpp *dpp = user_data;

	dpp->pkex_scan_id = 0;
}

static bool dpp_start_pkex_enrollee(struct dpp *dpp, const char *key,
				const char *identifier)
{
	_auto_(l_ecc_point_free) struct l_ecc_point *qi = NULL;

	dpp->sm = dpp_sm_new(dpp_event, dpp->boot_public,
				dpp->boot_private, dpp);

	if (identifier)
		dpp_sm_set_pkex_identifier(dpp->sm, identifier);

	dpp_sm_set_pkex_key(dpp->sm, key);
	dpp_sm_set_pkex_own_mac(dpp->sm, netdev_get_address(dpp->netdev));
	dpp_sm_set_role(dpp->sm, DPP_CAPABILITY_ENROLLEE);

	memcpy(dpp->peer_addr, broadcast, 6);
	dpp->role = DPP_CAPABILITY_ENROLLEE;
	dpp->interface = DPP_INTERFACE_PKEX;

	/*
	 * In theory a driver could support a lesser duration than 200ms. This
	 * complicates things since we would need to tack on additional
	 * offchannel requests to meet the 200ms requirement. This could be done
	 * but for now use max_roc or 200ms, whichever is less.
	 */
	dpp->dwell = (dpp->max_roc < 200) ? dpp->max_roc : 200;

	dpp_property_changed_notify(dpp);

	/*
	 * The 'dpp_default_freqs' function returns the default frequencies
	 * outlined in section 5.6.1. For 2.4/5GHz this is only 3 frequencies
	 * which is unlikely to result in discovery of a configurator. The spec
	 * does allow frequencies to be "obtained in a manner outside the scope
	 * of this specification" which is what is being done here.
	 *
	 * This is mainly geared towards IWD-based configurators; banking on the
	 * fact that they are currently connected to nearby APs. Scanning lets
	 * us see nearby BSS's which should be the same frequencies as our
	 * target configurator.
	 */
	l_debug("Performing scan for frequencies to start PKEX");

	dpp->pkex_scan_id = scan_active(dpp->wdev_id, NULL, 0,
				dpp_pkex_scan_trigger, dpp_pkex_scan_notify,
				dpp, dpp_pkex_scan_destroy);
	if (!dpp->pkex_scan_id)
		goto failed;

	return true;

failed:
	dpp_reset(dpp);
	return false;
}

static bool dpp_parse_pkex_args(struct l_dbus_message *message,
					const char **key_out,
					const char **id_out)
{
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter variant;
	const char *dict_key;
	const char *key = NULL;
	const char *id = NULL;

	if (!l_dbus_message_get_arguments(message, "a{sv}", &iter))
		return false;

	while (l_dbus_message_iter_next_entry(&iter, &dict_key, &variant)) {
		if (!strcmp(dict_key, "Code")) {
			if (!l_dbus_message_iter_get_variant(&variant, "s",
								&key))
				return false;
		} else if (!strcmp(dict_key, "Identifier")) {
			if (!l_dbus_message_iter_get_variant(&variant, "s",
								&id))
				return false;
		}
	}

	if (!key)
		return false;

	if (id && strlen(id) > 80)
		return false;

	*key_out = key;
	*id_out = id;

	return true;
}

static struct l_dbus_message *dpp_dbus_pkex_start_enrollee(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp *dpp = user_data;
	const char *key;
	const char *id;
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));

	l_debug("");

	if (dpp->sm || dpp->interface != DPP_INTERFACE_UNBOUND)
		return dbus_error_busy(message);

	if (station && station_get_connected_network(station))
		return dbus_error_busy(message);

	if (!dpp_parse_pkex_args(message, &key, &id))
		goto invalid_args;

	if (!dpp_start_pkex_enrollee(dpp, key, id))
		goto invalid_args;

	return l_dbus_message_new_method_return(message);

invalid_args:
	return dbus_error_invalid_args(message);
}

static void pkex_agent_disconnect(struct l_dbus *dbus, void *user_data)
{
	struct dpp *dpp = user_data;

	l_debug("SharedCodeAgent %s disconnected", dpp->agent->path);

	dpp_reset(dpp);
}

static void dpp_create_agent(struct dpp *dpp, const char *path,
					struct l_dbus_message *message)
{
	const char *sender = l_dbus_message_get_sender(message);

	dpp->agent = l_new(struct pkex_agent, 1);
	dpp->agent->owner = l_strdup(sender);
	dpp->agent->path = l_strdup(path);
	dpp->agent->disconnect_watch = l_dbus_add_disconnect_watch(
							dbus_get_bus(),
							sender,
							pkex_agent_disconnect,
							dpp, NULL);

	l_debug("Registered a SharedCodeAgent on path %s", path);
}

static struct l_dbus_message *dpp_start_pkex_configurator(struct dpp *dpp,
					const char *key, const char *identifier,
					const char *agent_path,
					struct l_dbus_message *message)
{
	struct handshake_state *hs = netdev_get_handshake(dpp->netdev);
	struct station *station = station_find(netdev_get_ifindex(dpp->netdev));
	struct network *network = station_get_connected_network(station);
	struct scan_bss *bss = station_get_connected_bss(station);
	const struct l_settings *settings;
	struct dpp_configuration *config;

	if (dpp->sm || dpp->interface != DPP_INTERFACE_UNBOUND)
		return dbus_error_busy(message);

	if (!dpp->mcast_support) {
		l_debug("Multicast frame registration not supported, cannot "
			"start a configurator");
		return dbus_error_not_supported(message);
	}

	if (!network || !bss)
		return dbus_error_not_connected(message);

	settings = network_get_settings(network);
	if (!settings) {
		l_debug("No settings for network, is this a known network?");
		return dbus_error_not_configured(message);
	}

	dpp->sm = dpp_sm_new(dpp_event, dpp->boot_public,
				dpp->boot_private, dpp);

	if (identifier)
		dpp_sm_set_pkex_identifier(dpp->sm, identifier);

	if (key)
		dpp_sm_set_pkex_key(dpp->sm, key);

	if (agent_path)
		dpp_create_agent(dpp, agent_path, message);

	dpp->role = DPP_CAPABILITY_CONFIGURATOR;
	dpp->interface = DPP_INTERFACE_PKEX;
	dpp->current_freq = bss->frequency;
	config = dpp_configuration_new(network_get_settings(network),
						network_get_ssid(network),
						hs->akm_suite);

	dpp_sm_set_role(dpp->sm, DPP_CAPABILITY_CONFIGURATOR);
	dpp_sm_set_configuration(dpp->sm, config);
	dpp_sm_set_pkex_own_mac(dpp->sm, netdev_get_address(dpp->netdev));
	dpp_sm_set_write_handler(dpp->sm, dpp_tx_frame);

	dpp_property_changed_notify(dpp);

	if (key)
		l_debug("Starting PKEX configurator for single enrollee");
	else
		l_debug("Starting PKEX configurator with agent");

	dpp_sm_pkex_start_responder(dpp->sm);

	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *dpp_dbus_pkex_configure_enrollee(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp *dpp = user_data;
	const char *key;
	const char *id;

	l_debug("");

	if (!dpp_parse_pkex_args(message, &key, &id))
		return dbus_error_invalid_args(message);

	return dpp_start_pkex_configurator(dpp, key, id, NULL, message);
}

static struct l_dbus_message *dpp_dbus_pkex_start_configurator(
						struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct dpp *dpp = user_data;
	const char *path;

	if (!l_dbus_message_get_arguments(message, "o", &path))
		return dbus_error_invalid_args(message);

	return dpp_start_pkex_configurator(dpp, NULL, NULL, path, message);
}

static void dpp_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "StartEnrollee", 0,
				dpp_dbus_start_enrollee, "s", "", "uri");
	l_dbus_interface_method(interface, "StartConfigurator", 0,
				dpp_dbus_start_configurator, "s", "", "uri");
	l_dbus_interface_method(interface, "ConfigureEnrollee", 0,
				dpp_dbus_configure_enrollee, "", "s", "uri");
	l_dbus_interface_method(interface, "Stop", 0,
				dpp_dbus_stop, "", "");

	l_dbus_interface_property(interface, "Started", 0, "b", dpp_get_started,
					NULL);
	l_dbus_interface_property(interface, "Role", 0, "s", dpp_get_role,
					NULL);
	l_dbus_interface_property(interface, "URI", 0, "s", dpp_get_uri, NULL);
}

static struct l_dbus_message *dpp_dbus_pkex_stop(struct l_dbus *dbus,
				struct l_dbus_message *message, void *user_data)
{
	struct dpp *dpp = user_data;

	l_debug("");

	if (dpp->interface != DPP_INTERFACE_PKEX)
		return dbus_error_not_found(message);

	dpp_reset(dpp);

	return l_dbus_message_new_method_return(message);
}

static void dpp_setup_pkex_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "StartEnrollee", 0,
			dpp_dbus_pkex_start_enrollee, "", "a{sv}", "args");
	l_dbus_interface_method(interface, "Stop", 0,
			dpp_dbus_pkex_stop, "", "");
	l_dbus_interface_method(interface, "ConfigureEnrollee", 0,
			dpp_dbus_pkex_configure_enrollee, "", "a{sv}", "args");
	l_dbus_interface_method(interface, "StartConfigurator", 0,
			dpp_dbus_pkex_start_configurator, "", "o", "path");

	l_dbus_interface_property(interface, "Started", 0, "b",
			dpp_pkex_get_started, NULL);
	l_dbus_interface_property(interface, "Role", 0, "s",
			dpp_pkex_get_role, NULL);
}

static void dpp_destroy_interface(void *user_data)
{
	struct dpp *dpp = user_data;

	if (--dpp->refcount)
		return;

	l_queue_remove(dpp_list, dpp);

	dpp_free(dpp);
}

static int dpp_init(void)
{
	nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to obtain nl80211");
		return -EIO;
	}

	netdev_watch = netdev_watch_add(dpp_netdev_watch, NULL, NULL);

	l_dbus_register_interface(dbus_get_bus(), IWD_DPP_INTERFACE,
					dpp_setup_interface,
					dpp_destroy_interface, false);
	l_dbus_register_interface(dbus_get_bus(), IWD_DPP_PKEX_INTERFACE,
					dpp_setup_pkex_interface,
					dpp_destroy_interface, false);

	mlme_watch = l_genl_family_register(nl80211, "mlme", dpp_mlme_notify,
						NULL, NULL);

	unicast_watch = l_genl_add_unicast_watch(iwd_get_genl(),
						NL80211_GENL_NAME,
						dpp_unicast_notify,
						NULL, NULL);

	dpp_list = l_queue_new();

	return 0;
}

static void dpp_exit(void)
{
	l_debug("");

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DPP_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), IWD_DPP_PKEX_INTERFACE);

	netdev_watch_remove(netdev_watch);

	l_genl_remove_unicast_watch(iwd_get_genl(), unicast_watch);

	l_genl_family_unregister(nl80211, mlme_watch);
	mlme_watch = 0;

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_queue_destroy(dpp_list, (l_queue_destroy_func_t) dpp_free);
}

IWD_MODULE(dpp, dpp_init, dpp_exit);
IWD_MODULE_DEPENDS(dpp, netdev);
