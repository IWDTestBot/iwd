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
	int16_t signal;
	uint32_t frequency;
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

static const char *get_signal(const void *data)
{
	const struct bss *bss = data;
	static char signal_str[7];

	sprintf(signal_str, "%d", bss->signal);

	return signal_str;
}

static void update_signal(void *data, struct l_dbus_message_iter *variant)
{
	struct bss *bss = data;
	int16_t value;

	if (!l_dbus_message_iter_get_variant(variant, "n", &value))
		return;

	bss->signal = value;
}

static const char *get_frequency(const void *data)
{
	const struct bss *bss = data;
	static char freq_str[5];

	sprintf(freq_str, "%u", bss->frequency);

	return freq_str;
}

static void update_frequency(void *data, struct l_dbus_message_iter *variant)
{
	struct bss *bss = data;
	uint32_t value;

	if (!l_dbus_message_iter_get_variant(variant, "u", &value))
		return;

	bss->frequency = value;
}

static const struct proxy_interface_property bss_properties[] = {
	{ "Address",        "s", update_address, get_address },
	{ "SignalStrength", "n", update_signal, get_signal },
	{ "Frequency",      "u", update_frequency, get_frequency },
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
