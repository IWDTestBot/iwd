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

#include <stdlib.h>
#include <stdio.h>
#include <linux/if_ether.h>

#include <ell/ell.h>
#include "ell/useful.h"

#include "src/module.h"
#include "src/util.h"
#include "src/dbus.h"
#include "hwsim.h"

#define HWSIM_MAX_PREFIX_LEN		128
#define HWSIM_DELAY_MIN_MS		1

#define HWSIM_RULE_MANAGER_INTERFACE HWSIM_SERVICE ".RuleManager"
#define HWSIM_RULE_INTERFACE HWSIM_SERVICE ".Rule"

struct hwsim_rule {
	unsigned int id;
	uint8_t source[ETH_ALEN];
	uint8_t destination[ETH_ALEN];
	bool source_any : 1;
	bool destination_any : 1;
	bool bidirectional : 1;
	bool drop : 1;
	bool drop_ack : 1;
	bool enabled : 1;
	uint32_t frequency;
	int priority;
	int signal;
	int delay;
	uint8_t *prefix;
	size_t prefix_len;
	uint8_t *match;
	size_t match_len;
	uint16_t match_offset;
	int match_times; /* negative value indicates unused */
};

struct delay_frame_info {
	struct hwsim_frame *frame;
	struct radio_info_rec *radio;
};

static struct l_queue *rules;
static unsigned int next_rule_id;

static const char *rule_get_path(struct hwsim_rule *rule)
{
	static char path[16];

	snprintf(path, sizeof(path), "/rule%u", rule->id);

	return path;
}

static int rule_compare_priority(const void *a, const void *b, void *user)
{
	const struct hwsim_rule *rule_a = a;
	const struct hwsim_rule *rule_b = b;

	return (rule_a->priority > rule_b->priority) ? 1 : -1;
}

static struct l_dbus_message *rule_add(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct hwsim_rule *rule;
	const char *path;
	struct l_dbus_message *reply;

	rule = l_new(struct hwsim_rule, 1);
	rule->id = next_rule_id++;
	rule->source_any = true;
	rule->destination_any = true;
	rule->delay = 0;
	rule->enabled = false;
	rule->match_times = -1;
	rule->drop_ack = true;

	if (!rules)
		rules = l_queue_new();

	l_queue_insert(rules, rule, rule_compare_priority, NULL);
	path = rule_get_path(rule);

	if (!l_dbus_object_add_interface(dbus, path,
					HWSIM_RULE_INTERFACE, rule))
		l_info("Unable to add the %s interface to %s",
				HWSIM_RULE_INTERFACE, path);

	if (!l_dbus_object_add_interface(dbus, path,
					L_DBUS_INTERFACE_PROPERTIES, NULL))
		l_info("Unable to add the %s interface to %s",
				L_DBUS_INTERFACE_PROPERTIES, path);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "o", path);

	return reply;
}

static void setup_rule_manager_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "AddRule", 0,
				rule_add, "o", "", "path");
}

static void destroy_rule(void *user_data)
{
	struct hwsim_rule *rule = user_data;

	if (rule->prefix)
		l_free(rule->prefix);

	if (rule->match)
		l_free(rule->match);

	l_free(rule);
}

static struct l_dbus_message *rule_remove(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *path;

	path = rule_get_path(rule);
	l_queue_remove(rules, rule);

	destroy_rule(rule);

	l_dbus_unregister_object(dbus, path);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_source(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (rule->source_any)
		str = "any";
	else
		str = util_address_to_string(rule->source);

	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static struct l_dbus_message *rule_property_set_source(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &str))
		return dbus_error_invalid_args(message);

	if (!strcmp(str, "any"))
		rule->source_any = true;
	else {
		if (!util_string_to_address(str, rule->source))
			return dbus_error_invalid_args(message);

		rule->source_any = false;
	}

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_destination(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (rule->destination_any)
		str = "any";
	else if (util_is_broadcast_address(rule->destination))
		str = "multicast";
	else
		str = util_address_to_string(rule->destination);

	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static struct l_dbus_message *rule_property_set_destination(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	const char *str;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &str))
		return dbus_error_invalid_args(message);

	if (!strcmp(str, "any"))
		rule->destination_any = true;
	else if (!strcmp(str, "multicast")) {
		rule->destination[0] = 0x80;
		rule->destination_any = false;
	} else {
		if (!util_string_to_address(str, rule->destination))
			return dbus_error_invalid_args(message);

		rule->destination_any = false;
	}

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_bidirectional(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->bidirectional;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_bidirectional(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->bidirectional = bval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_frequency(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;

	l_dbus_message_builder_append_basic(builder, 'u', &rule->frequency);

	return true;
}

static struct l_dbus_message *rule_property_set_frequency(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &rule->frequency))
		return dbus_error_invalid_args(message);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_priority(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval = rule->priority;

	l_dbus_message_builder_append_basic(builder, 'n', &intval);

	return true;
}

static struct l_dbus_message *rule_property_set_priority(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval;

	if (!l_dbus_message_iter_get_variant(new_value, "n", &intval))
		return dbus_error_invalid_args(message);

	rule->priority = intval;
	l_queue_remove(rules, rule);
	l_queue_insert(rules, rule, rule_compare_priority, NULL);

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_signal(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval = rule->signal;

	l_dbus_message_builder_append_basic(builder, 'n', &intval);

	return true;
}

static struct l_dbus_message *rule_property_set_signal(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	int16_t intval;

	if (!l_dbus_message_iter_get_variant(new_value, "n", &intval) ||
			intval > 0 || intval < -10000)
		return dbus_error_invalid_args(message);

	rule->signal = intval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_drop(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->drop;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_drop(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->drop = bval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_delay(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;

	l_dbus_message_builder_append_basic(builder, 'u', &rule->delay);

	return true;
}

static struct l_dbus_message *rule_property_set_delay(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	uint32_t val;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &val) ||
				val < HWSIM_DELAY_MIN_MS)
		return dbus_error_invalid_args(message);

	rule->delay = val;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_prefix(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	size_t i;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < rule->prefix_len; i++)
		l_dbus_message_builder_append_basic(builder, 'y',
							rule->prefix + i);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static struct l_dbus_message *rule_property_set_prefix(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	struct l_dbus_message_iter iter;
	const uint8_t *prefix;
	uint32_t len;

	if (!l_dbus_message_iter_get_variant(new_value, "ay", &iter))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&iter,
						(const void **)&prefix, &len))
		goto invalid_args;

	if (len > HWSIM_MAX_PREFIX_LEN)
		goto invalid_args;

	if (rule->prefix)
		l_free(rule->prefix);

	rule->prefix = l_memdup(prefix, len);
	rule->prefix_len = len;

	return l_dbus_message_new_method_return(message);

invalid_args:
	return dbus_error_invalid_args(message);
}

static bool rule_property_get_match(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	size_t i;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < rule->match_len; i++)
		l_dbus_message_builder_append_basic(builder, 'y',
							rule->match + i);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static struct l_dbus_message *rule_property_set_match(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	struct l_dbus_message_iter iter;
	const uint8_t *match;
	uint32_t len;

	if (!l_dbus_message_iter_get_variant(new_value, "ay", &iter))
		goto invalid_args;

	if (!l_dbus_message_iter_get_fixed_array(&iter,
						(const void **)&match, &len))
		goto invalid_args;

	if (len > HWSIM_MAX_PREFIX_LEN)
		goto invalid_args;

	if (rule->match)
		l_free(rule->match);

	rule->match = l_memdup(match, len);
	rule->match_len = len;

	return l_dbus_message_new_method_return(message);

invalid_args:
	return dbus_error_invalid_args(message);
}

static bool rule_property_get_match_offset(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	uint16_t val = rule->match_offset;

	l_dbus_message_builder_append_basic(builder, 'q', &val);

	return true;
}

static struct l_dbus_message *rule_property_set_match_offset(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	uint16_t val;

	if (!l_dbus_message_iter_get_variant(new_value, "q", &val))
		return dbus_error_invalid_args(message);

	rule->match_offset = val;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_enabled(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->enabled;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_enabled(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->enabled = bval;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_match_times(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	uint16_t val = rule->match_times;

	l_dbus_message_builder_append_basic(builder, 'q', &val);

	return true;
}

static struct l_dbus_message *rule_property_set_match_times(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	uint16_t val;

	if (!l_dbus_message_iter_get_variant(new_value, "q", &val))
		return dbus_error_invalid_args(message);

	rule->match_times = val;

	return l_dbus_message_new_method_return(message);
}

static bool rule_property_get_drop_ack(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval = rule->drop_ack;

	l_dbus_message_builder_append_basic(builder, 'b', &bval);

	return true;
}

static struct l_dbus_message *rule_property_set_drop_ack(
					struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct hwsim_rule *rule = user_data;
	bool bval;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &bval))
		return dbus_error_invalid_args(message);

	rule->drop_ack = bval;

	return l_dbus_message_new_method_return(message);
}

static void setup_rule_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Remove", 0, rule_remove, "", "");

	l_dbus_interface_property(interface, "Source",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "s",
					rule_property_get_source,
					rule_property_set_source);
	l_dbus_interface_property(interface, "Destination",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "s",
					rule_property_get_destination,
					rule_property_set_destination);
	l_dbus_interface_property(interface, "Bidirectional",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_bidirectional,
					rule_property_set_bidirectional);
	l_dbus_interface_property(interface, "Frequency",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "u",
					rule_property_get_frequency,
					rule_property_set_frequency);
	l_dbus_interface_property(interface, "Priority",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "n",
					rule_property_get_priority,
					rule_property_set_priority);
	l_dbus_interface_property(interface, "SignalStrength",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "n",
					rule_property_get_signal,
					rule_property_set_signal);
	l_dbus_interface_property(interface, "Drop",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_drop,
					rule_property_set_drop);
	l_dbus_interface_property(interface, "Delay",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "u",
					rule_property_get_delay,
					rule_property_set_delay);
	l_dbus_interface_property(interface, "Prefix",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "ay",
					rule_property_get_prefix,
					rule_property_set_prefix);
	l_dbus_interface_property(interface, "MatchBytes",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "ay",
					rule_property_get_match,
					rule_property_set_match);
	l_dbus_interface_property(interface, "MatchBytesOffset",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "q",
					rule_property_get_match_offset,
					rule_property_set_match_offset);
	l_dbus_interface_property(interface, "Enabled",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_enabled,
					rule_property_set_enabled);
	l_dbus_interface_property(interface, "MatchTimes",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "q",
					rule_property_get_match_times,
					rule_property_set_match_times);
	l_dbus_interface_property(interface, "DropAck",
					L_DBUS_PROPERTY_FLAG_AUTO_EMIT, "b",
					rule_property_get_drop_ack,
					rule_property_set_drop_ack);
}

static bool radio_match_addr(const struct radio_info_rec *radio,
				const uint8_t *addr)
{
	if (!radio || util_is_broadcast_address(addr))
		return !radio && util_is_broadcast_address(addr);

	return !memcmp(addr, radio->addrs[0], ETH_ALEN) ||
		!memcmp(addr, radio->addrs[1], ETH_ALEN);
}

static void process_rules(const struct radio_info_rec *src_radio,
				const struct radio_info_rec *dst_radio,
				struct hwsim_frame *frame, bool ack, bool *drop,
				uint32_t *delay)
{
	const struct l_queue_entry *rule_entry;

	for (rule_entry = l_queue_get_entries(rules); rule_entry;
			rule_entry = rule_entry->next) {
		struct hwsim_rule *rule = rule_entry->data;

		if (!rule->enabled)
			continue;

		if (!rule->source_any &&
				!radio_match_addr(src_radio, rule->source) &&
				(!rule->bidirectional ||
				 !radio_match_addr(dst_radio, rule->source)))
			continue;

		if (!rule->destination_any &&
				!radio_match_addr(dst_radio,
							rule->destination) &&
				(!rule->bidirectional ||
				 !radio_match_addr(src_radio,
							rule->destination)))
			continue;

		/*
		 * If source matches only because rule->bidirectional was
		 * true, make sure destination is "any" or matches source
		 * radio's address.
		 */
		if (!rule->source_any && rule->bidirectional &&
				radio_match_addr(dst_radio, rule->source))
			if (!rule->destination_any &&
					!radio_match_addr(dst_radio,
							rule->destination))
				continue;

		if (rule->frequency && rule->frequency != frame->frequency)
			continue;

		if (rule->prefix && frame->payload_len >= rule->prefix_len) {
			if (memcmp(rule->prefix, frame->payload,
					rule->prefix_len) != 0)
				continue;
		}

		if (rule->match && frame->payload_len >=
					rule->match_len + rule->match_offset) {
			if (memcmp(rule->match,
					frame->payload + rule->match_offset,
					rule->match_len))
				continue;
		}

		/* Rule deemed to match frame, apply any changes */
		if (rule->match_times == 0)
			continue;

		if (rule->signal)
			frame->signal = rule->signal / 100;

		/* Don't drop if this is an ACK, unless drop_ack is set */
		if (!ack || (ack && rule->drop_ack))
			*drop = rule->drop;

		if (delay)
			*delay = rule->delay;

		if (rule->match_times > 0)
			rule->match_times--;
	}
}

static void send_frame_callback(struct l_genl_msg *msg, void *user_data)
{
	struct delay_frame_info *info = user_data;

	if (l_genl_msg_get_error(msg) == 0) {
		info->frame->acked = true;
		info->frame->ack_radio = info->radio;
	}

	info->frame->pending_callback_count--;
}

static void ack_frame(struct hwsim_frame *frame)
{
	if (!frame->pending_callback_count) {
		/*
		 * Apparently done with this frame, send tx info and signal
		 * the returning of an ACK frame in the opposite direction.
		 */

		if (!(frame->flags & HWSIM_TX_CTL_NO_ACK) && frame->acked) {
			bool drop = false;

			process_rules(frame->ack_radio, frame->src_radio,
					frame, true, &drop, NULL);

			if (!drop)
				frame->flags |= HWSIM_TX_STAT_ACK;
		}

		if (frame->src_radio)
			hwsim_send_tx_info(frame);
	}
}

static void send_frame_destroy(void *user_data)
{
	struct delay_frame_info *info = user_data;
	struct hwsim_frame *frame = info->frame;

	if (frame->refcount > 1) {
		hwsim_frame_unref(frame);
		l_free(info);

		return;
	}

	ack_frame(frame);
}

static void frame_delay_callback(struct l_timeout *timeout, void *user_data)
{
	struct delay_frame_info *info = user_data;

	if (hwsim_send_frame(info->frame, info->radio, send_frame_callback,
				info, send_frame_destroy))
		info->frame->pending_callback_count++;
	else
		send_frame_destroy(info);

	if (timeout)
		l_timeout_remove(timeout);
}

/*
 * Process frames in a similar way to how the kernel built-in hwsim medium
 * does this, with an additional optimization for unicast frames and
 * additional modifications to frames decided by user-configurable rules.
 */
static void rules_process_frame(struct hwsim_frame *frame, void *user_data)
{
	const struct l_queue_entry *entry;
	bool drop_mcast = false;
	bool beacon = false;

	/* Unknown source, ignore */
	if (!frame->src_radio)
		return;

	if (util_is_broadcast_address(frame->dst_ether_addr))
		process_rules(frame->src_radio, NULL, frame, false,
				&drop_mcast, NULL);

	if (frame->payload_len >= 2 &&
			frame->payload[0] == 0x80 &&
			frame->payload[1] == 0x00)
		beacon = true;

	for (entry = hwsim_get_radios(); entry; entry = entry->next) {
		struct radio_info_rec *radio = entry->data;
		struct delay_frame_info *info;
		bool drop = drop_mcast;
		uint32_t delay = 0;
		const struct l_queue_entry *i;

		if (radio == frame->src_radio)
			continue;

		/*
		 * The kernel hwsim medium passes multicast frames to all
		 * radios that are on the same frequency as this frame but
		 * the netlink medium API only lets userspace pass frames to
		 * radios by known hardware address.  It does check that the
		 * receiving radio is on the same frequency though so we can
		 * send to all known addresses.
		 *
		 * If the frame's Receiver Address (RA) is a multicast
		 * address, then send the frame to every radio that is
		 * registered.  If it's a unicast address then optimize
		 * by only forwarding the frame to the radios that have
		 * at least one interface with this specific address.
		 */
		if (!util_is_broadcast_address(frame->dst_ether_addr)) {
			for (i = hwsim_get_interfaces(); i; i = i->next) {
				struct interface_info_rec *interface = i->data;

				if (interface->radio_rec != radio)
					continue;

				if (!memcmp(interface->addr,
						frame->dst_ether_addr,
						ETH_ALEN))
					break;
			}

			if (!i)
				continue;
		}

		process_rules(frame->src_radio, radio, frame, false,
				&drop, &delay);

		if (drop)
			continue;

		/*
		 * Don't bother sending beacons to other AP interfaces
		 * if the AP interface is the only one on this phy
		 */
		if (beacon && radio->ap_only)
			continue;

		info = l_new(struct delay_frame_info, 1);
		info->radio = radio;
		info->frame = hwsim_frame_ref(frame);

		if (delay) {
			if (!l_timeout_create_ms(delay, frame_delay_callback,
							info, NULL)) {
				l_error("Error delaying frame %ums, "
						"frame will be dropped", delay);
				hwsim_frame_unref(info->frame);
				l_free(info);
			}
		} else
			frame_delay_callback(NULL, info);
	}

	/*
	 * If the frame was dropped to all radios we still need to signal this
	 * information to the kernel.
	 */
	ack_frame(frame);
}

static int rules_init(void)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_debug("");

	if (!l_dbus_register_interface(dbus, HWSIM_RULE_MANAGER_INTERFACE,
					setup_rule_manager_interface,
					NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RULE_MANAGER_INTERFACE);
		return -EINVAL;
	}

	if (!l_dbus_register_interface(dbus, HWSIM_RULE_INTERFACE,
					setup_rule_interface, NULL, false)) {
		l_error("Unable to register the %s interface",
			HWSIM_RULE_INTERFACE);
		return -EINVAL;
	}

	if (!l_dbus_object_add_interface(dbus, "/",
						HWSIM_RULE_MANAGER_INTERFACE,
						NULL)) {
		l_info("Unable to add the %s interface to /",
			HWSIM_RULE_MANAGER_INTERFACE);
		return -EINVAL;
	}

	hwsim_watch_register(rules_process_frame, NULL, NULL);

	return 0;
}

static void rules_exit(void)
{
	l_queue_destroy(rules, destroy_rule);
}

IWD_MODULE(rules, rules_init, rules_exit);
