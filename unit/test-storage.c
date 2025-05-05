/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2025  Locus Robotics. All rights reserved.
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

#include <assert.h>

#include <ell/ell.h>

#include "src/storage.h"

static void test_short_encrypted_bytes(const void *data)
{
	struct l_settings *settings = l_settings_new();
	bool changed;

	l_settings_set_string(settings, "Security", "EncryptedSecurity", "012345");
	l_settings_set_string(settings, "Security", "EncryptedSalt", "012345");

	assert(__storage_decrypt(settings, "mySSID", &changed) < 0);
	l_settings_free(settings);
}

int main(int argc, char *argv[])
{
	int ret;

	l_test_init(&argc, &argv);

	storage_init((const uint8_t *)"abc123", 6);

	if (l_cipher_is_supported(L_CIPHER_AES_CTR))
		l_test_add("/storage/profile encryption",
			test_short_encrypted_bytes, NULL);

	ret = l_test_run();

	storage_exit();

	return ret;
}
