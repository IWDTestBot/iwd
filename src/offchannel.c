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

#include "src/offchannel.h"
#include "src/wiphy.h"
#include "src/nl80211util.h"
#include "src/iwd.h"
#include "src/module.h"

struct offchannel_info {
	uint64_t wdev_id;
	uint32_t freq;
	uint32_t duration;

	uint32_t roc_cmd_id;
	uint64_t roc_cookie;
	uint64_t early_cookie;

	offchannel_started_cb_t started;
	offchannel_destroy_cb_t destroy;
	void *user_data;
	int error;

	struct wiphy_radio_work_item work;

	bool needs_cancel : 1;
};

struct match_data {
	uint64_t wdev_id;
	uint64_t cookie;
};

static struct l_genl_family *nl80211;
static struct l_queue *offchannel_list;

static bool match_info(const void *a, const void *user_data)
{
	const struct match_data *match = user_data;
	const struct offchannel_info *info = a;

	if (match->wdev_id != info->wdev_id)
		return false;

	if (!match->cookie)
		return true;

	return match->cookie == info->roc_cookie;
}

static bool match_id(const void *a, const void *user_data)
{
	const uint32_t *id = user_data;
	const struct offchannel_info *info = a;

	return *id == info->work.id;
}

static void offchannel_cancel_roc(struct offchannel_info *info)
{
	struct l_genl_msg *msg;

	msg = l_genl_msg_new(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &info->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_COOKIE, 8, &info->roc_cookie);

	/* Nothing much can be done if this fails */
	if (!l_genl_family_send(nl80211, msg, NULL, NULL, NULL))
		l_genl_msg_unref(msg);
}

static void offchannel_roc_cb(struct l_genl_msg *msg, void *user_data)
{
	struct offchannel_info *info = user_data;

	info->error = l_genl_msg_get_error(msg);
	info->roc_cmd_id = 0;

	if (info->error < 0) {
		l_debug("Error from CMD_REMAIN_ON_CHANNEL (%d)", info->error);
		goto work_done;
	}

	info->error = nl80211_parse_attrs(msg, NL80211_ATTR_COOKIE,
					&info->roc_cookie, NL80211_ATTR_UNSPEC);
	if (info->error < 0) {
		l_error("Could not parse ROC cookie");
		goto work_done;
	}

	/*
	 * If this request was cancelled prior to the request ever hitting the
	 * kernel, cancel now.
	 *
	 * If the ROC event came before the ACK, call back now since the
	 * callback was skipped in the notify event. There is the potential that
	 * an external process issued the ROC, but if the cookies don't match
	 * here we can be sure it wasn't for us.
	 */
	if (info->needs_cancel)
		offchannel_cancel_roc(info);
	else if (info->early_cookie == info->roc_cookie && info->started)
		info->started(info->user_data);

	return;

work_done:
	wiphy_radio_work_done(wiphy_find_by_wdev(info->wdev_id), info->work.id);
}

static bool offchannel_work_ready(struct wiphy_radio_work_item *item)
{
	struct l_genl_msg *msg;
	struct offchannel_info *info = l_container_of(item,
						struct offchannel_info, work);

	msg = l_genl_msg_new(NL80211_CMD_REMAIN_ON_CHANNEL);

	l_genl_msg_append_attr(msg, NL80211_ATTR_WDEV, 8, &info->wdev_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &info->freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_DURATION, 4, &info->duration);

	info->roc_cmd_id = l_genl_family_send(nl80211, msg, offchannel_roc_cb,
						info, NULL);
	if (!info->roc_cmd_id) {
		info->error = -EIO;
		l_genl_msg_unref(msg);
		return true;
	}

	l_queue_push_head(offchannel_list, info);

	return false;
}

static void offchannel_work_destroy(struct wiphy_radio_work_item *item)
{
	struct offchannel_info *info = l_container_of(item,
						struct offchannel_info, work);

	if (info->destroy)
		info->destroy(info->error, info->user_data);

	l_queue_remove(offchannel_list, info);
	l_free(info);
}

static const struct wiphy_radio_work_item_ops offchannel_work_ops = {
	.do_work = offchannel_work_ready,
	.destroy = offchannel_work_destroy,
};

uint32_t offchannel_start(uint64_t wdev_id, int priority, uint32_t freq,
			uint32_t duration, offchannel_started_cb_t started,
			void *user_data, offchannel_destroy_cb_t destroy)
{
	struct offchannel_info *info = l_new(struct offchannel_info, 1);

	info->wdev_id = wdev_id;
	info->freq = freq;
	info->duration = duration;
	info->started = started;
	info->destroy = destroy;
	info->user_data = user_data;
	/*
	 * Set error as cancelled in case this work gets cancelled prior to
	 * the wiphy work starting.
	 */
	info->error = -ECANCELED;

	return wiphy_radio_work_insert(wiphy_find_by_wdev(wdev_id), &info->work,
					priority, &offchannel_work_ops);
}

void offchannel_cancel(uint64_t wdev_id, uint32_t id)
{
	struct wiphy *wiphy = wiphy_find_by_wdev(wdev_id);
	struct offchannel_info *info;
	int ret;

	if (!wiphy)
		return;

	/*
	 * Exit if work does not exist, if it hasn't started 'done' the work,
	 * otherwise decide how the work needs to be canceled.
	 */
	ret = wiphy_radio_work_is_running(wiphy, id);
	if (ret < 0)
		return;
	else if (ret == false)
		goto work_done;


	info = l_queue_find(offchannel_list, match_id, &id);
	if (!info)
		return;

	if (info->roc_cmd_id) {
		/*
		 * If the command hasn't left the genl queue it can be cancelled
		 * without any further action. Otherwise command has been sent
		 * to the kernel and we must wait until ROC starts and cancel at
		 * that time.
		 */
		if (!l_genl_family_request_sent(nl80211, info->roc_cmd_id)) {
			l_genl_family_cancel(nl80211, info->roc_cmd_id);
			info->roc_cmd_id = 0;
			goto work_done;
		}

		/* Lets the ROC callback know it needs to cancel the request */
		info->needs_cancel = true;

		goto destroy;
	}

	/*
	 * Something weird must have happened on the kernel side. This error
	 * will already be handled in offchannel_roc_cb but warn here to inform
	 * the user.
	 */
	if (L_WARN_ON(!info->roc_cookie))
		return;

	/*
	 * At this point we know ROC has at least been queued (potentially not
	 * started) and can be cancelled. The work will be completed once the
	 * kernel sends the cancel ROC event.
	 */
	offchannel_cancel_roc(info);

destroy:
	if (info->destroy)
		info->destroy(-ECANCELED, info->user_data);

	info->destroy = NULL;
	info->started = NULL;
	info->user_data = NULL;

	return;

work_done:
	wiphy_radio_work_done(wiphy, id);
}

static void offchannel_mlme_notify(struct l_genl_msg *msg, void *user_data)
{
	struct offchannel_info *info;
	struct match_data match = {0};
	uint64_t wdev_id;
	uint64_t cookie;
	uint8_t cmd;

	cmd = l_genl_msg_get_command(msg);

	if (cmd != NL80211_CMD_REMAIN_ON_CHANNEL &&
			cmd != NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
		return;

	if (nl80211_parse_attrs(msg, NL80211_ATTR_WDEV, &wdev_id,
					NL80211_ATTR_COOKIE, &cookie,
					NL80211_ATTR_UNSPEC) < 0)
		return;

	match.wdev_id = wdev_id;
	match.cookie = cookie;

	info = l_queue_find(offchannel_list, match_info, &match);
	if (!info) {
		/* Try again without cookie */
		match.cookie = 0;
		info = l_queue_find(offchannel_list, match_info, &match);
	}

	if (!info)
		return;

	/*
	 * If the cookie is zero and there is a pending ROC command there are
	 * two possibilities:
	 *   - The ACK callback came out of order. This has been seen in UML
	 *     when an offchannel request is canceled followed by another
	 *     request on the same channel. To handle this delay the started
	 *     callback until the ACK comes in when we can check the cookie.
	 *
	 *   - Event came from external process doing ROC. Checking the cookie
	 *     in the ACK lets us verify if this is the case.
	 *
	 * If the cookie is set but does not match, this ROC request came from
	 * outside IWD.
	 */
	if (!info->roc_cookie && info->roc_cmd_id) {
		info->early_cookie = cookie;
		return;
	} else if (info->roc_cookie != cookie)
		return;

	switch (cmd) {
	case NL80211_CMD_REMAIN_ON_CHANNEL:
		if (info->started)
			info->started(info->user_data);

		break;
	case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
		info->error = 0;

		wiphy_radio_work_done(wiphy_find_by_wdev(info->wdev_id),
					info->work.id);
		break;
	default:
		return;
	}
}

static int offchannel_init(void)
{
	struct l_genl *genl = iwd_get_genl();

	nl80211 = l_genl_family_new(genl, NL80211_GENL_NAME);
	if (!nl80211) {
		l_error("Failed to obtain nl80211");
		return -EIO;
	}

	if (!l_genl_family_register(nl80211, "mlme", offchannel_mlme_notify,
								NULL, NULL)) {
		l_error("Failed to register for MLME");
		l_genl_family_free(nl80211);
		nl80211 = NULL;

		return -EIO;
	}

	offchannel_list = l_queue_new();

	return 0;
}

static void offchannel_exit(void)
{
	l_debug("");

	l_genl_family_free(nl80211);
	nl80211 = NULL;

	l_queue_destroy(offchannel_list, l_free);
}

IWD_MODULE(offchannel, offchannel_init, offchannel_exit);
IWD_MODULE_DEPENDS(offchannel, wiphy);
