/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2024, Locus Robotics
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

#include <ell/ell.h>
#include "ell/useful.h"

#include "client/dbus-proxy.h"
#include "client/display.h"

struct bss {
	char *address;
	char *rsn;
};

static const char *get_address(const void *data)
{
	const struct bss *bss = data;

	return bss->address;
}

static void update_address(void *data, struct l_dbus_message_iter *variant)
{
	struct bss *bss = data;
	const char *value;

	l_free(bss->address);

	if (!l_dbus_message_iter_get_variant(variant, "s", &value)) {
		bss->address = NULL;

		return;
	}

	bss->address = l_strdup(value);
}

static char *string_array_to_string(struct l_dbus_message_iter *variant)
{
	struct l_dbus_message_iter array;
	const char *value;
	char **strv;
	char *result;

	if (!l_dbus_message_iter_get_variant(variant, "as", &array))
		return NULL;

	strv = l_strv_new();

	while (l_dbus_message_iter_next_entry(&array, &value))
		strv = l_strv_append(strv, value);

	result = l_strjoinv(strv, ' ');
	l_strv_free(strv);

	return result;
}

static void update_rsn(void *data, struct l_dbus_message_iter *variant)
{
	struct bss *bss = data;
	struct l_dbus_message_iter dict;
	struct l_dbus_message_iter value;
	const char *key;
	const char *group_value;
	char *key_mgmt = NULL;
	char *pairwise = NULL;
	char *group = NULL;

	l_free(bss->rsn);
	bss->rsn = NULL;

	if (!variant ||
			!l_dbus_message_iter_get_variant(variant, "a{sv}", &dict))
		goto done;

	while (l_dbus_message_iter_next_entry(&dict, &key, &value)) {
		if (!strcmp(key, "KeyMgmt")) {
			l_free(key_mgmt);
			key_mgmt = string_array_to_string(&value);
		} else if (!strcmp(key, "Pairwise")) {
			l_free(pairwise);
			pairwise = string_array_to_string(&value);
		} else if (!strcmp(key, "Group") &&
				l_dbus_message_iter_get_variant(&value, "s",
								&group_value)) {
			l_free(group);
			group = l_strdup(group_value);
		}
	}

	if (!key_mgmt || !pairwise || !group)
		goto done;

	bss->rsn = l_strdup_printf("KeyMgmt: %s; Pairwise: %s; Group: %s",
					key_mgmt, pairwise, group);

done:
	l_free(key_mgmt);
	l_free(pairwise);
	l_free(group);
}

static const char *get_rsn(const void *data)
{
	const struct bss *bss = data;

	return bss->rsn;
}

static const struct proxy_interface_property bss_properties[] = {
	{ "Address",       "s", update_address, get_address },
	{ "RSN",           "a{sv}", update_rsn, get_rsn },
	{ }
};

static void *bss_create(void)
{
	return l_new(struct bss, 1);
}

static void bss_destroy(void *data)
{
	struct bss *bss = data;

	l_free(bss->address);
	l_free(bss->rsn);
	l_free(bss);
}

static void bss_display_inline(const char *margin, const void *data)
{
	const struct bss *bss = data;

	display("%s%s\n", margin, bss->address);
}

static const struct proxy_interface_type_ops ops = {
	.create = bss_create,
	.destroy = bss_destroy,
	.display = bss_display_inline,
};

static struct proxy_interface_type bss_interface_type = {
	.interface = IWD_BSS_INTERFACE,
	.properties = bss_properties,
	.ops = &ops,
};

static int bss_interface_init(void)
{
	proxy_interface_type_register(&bss_interface_type);

	return 0;
}

static void bss_interface_exit(void)
{
	proxy_interface_type_unregister(&bss_interface_type);
}

INTERFACE_TYPE(bss_interface_type, bss_interface_init, bss_interface_exit)
