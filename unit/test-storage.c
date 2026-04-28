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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ell/ell.h>

#include "src/storage.h"

static bool aes_ctr_supported(const void *data)
{
	return l_cipher_is_supported(L_CIPHER_AES_CTR);
}

static char *create_profile_file(const char *data)
{
	char path[] = "/tmp/iwd-storage-test-XXXXXX";
	size_t len = strlen(data);
	int fd;

	fd = mkstemp(path);
	assert(fd >= 0);

	assert(write(fd, data, len) == (ssize_t) len);
	assert(close(fd) == 0);

	return l_strdup(path);
}

static char *read_profile_file(const char *path)
{
	char buffer[4096];
	ssize_t len;

	len = read_file(buffer, sizeof(buffer) - 1, "%s", path);
	assert(len >= 0);

	buffer[len] = '\0';

	return l_strdup(buffer);
}

static struct l_settings *create_unencrypted_psk_settings(
					bool externally_managed)
{
	struct l_settings *settings = l_settings_new();

	if (externally_managed)
		l_settings_set_bool(settings, "Settings",
					"ExternallyManaged", true);

	l_settings_set_string(settings, "Security", "Passphrase",
				"test-password");

	return settings;
}

static void test_short_encrypted_bytes(const void *data)
{
	struct l_settings *settings = l_settings_new();
	bool changed;
	int err;

	storage_init((const uint8_t *)"abc123", 6);

	l_settings_set_string(settings, "Security", "EncryptedSecurity", "012345");
	l_settings_set_string(settings, "Security", "EncryptedSalt", "012345");

	err = __storage_decrypt(settings, "mySSID", &changed);
	assert(err == -EBADMSG);

	l_settings_free(settings);

	storage_exit();
}

static void test_decrypt_encrypts_profile(const void *data)
{
	static const char profile[] =
		"[Security]\n"
		"Passphrase=test-password\n";
	struct l_settings *settings;
	char *path;
	char *contents;

	storage_init((const uint8_t *)"abc123", 6);

	settings = create_unencrypted_psk_settings(false);
	path = create_profile_file(profile);

	assert(storage_decrypt(settings, path, "mySSID"));

	contents = read_profile_file(path);
	assert(strstr(contents, "EncryptedSecurity="));
	assert(!strstr(contents, "Passphrase=test-password"));

	l_free(contents);
	unlink(path);
	l_free(path);
	l_settings_free(settings);

	storage_exit();
}

static void test_decrypt_externally_managed_profile(const void *data)
{
	static const char profile[] =
		"[Settings]\n"
		"ExternallyManaged=true\n"
		"\n"
		"[Security]\n"
		"Passphrase=test-password\n";
	struct l_settings *settings;
	char *path;
	char *contents;

	storage_init((const uint8_t *)"abc123", 6);

	settings = create_unencrypted_psk_settings(true);
	path = create_profile_file(profile);

	assert(storage_decrypt(settings, path, "mySSID"));

	contents = read_profile_file(path);
	assert(!strcmp(contents, profile));

	l_free(contents);
	unlink(path);
	l_free(path);
	l_settings_free(settings);

	storage_exit();
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_func_precheck("/storage/profile encryption",
							test_short_encrypted_bytes,
							aes_ctr_supported, 0);
	l_test_add_func_precheck("/storage/profile encryption write",
							test_decrypt_encrypts_profile,
							aes_ctr_supported, 0);
	l_test_add_func_precheck("/storage/externally managed profile",
					test_decrypt_externally_managed_profile,
					aes_ctr_supported, 0);

	return l_test_run();
}
