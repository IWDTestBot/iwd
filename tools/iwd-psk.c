/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <ell/ell.h>

#include "ell/useful.h"
#include "src/crypto.h"

static void usage(const char *exec_name)
{
	printf("%s - Generate a psk from passphrase\n"
		"Usage:\n", exec_name);
	printf("\%s <ssid> <passphrase>\n", exec_name);
	printf("\n");
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	unsigned char *ssid;
	size_t ssid_len;
	const char *passphrase;
	uint8_t psk[32];
	char *hexpsk;
	int err;

	if (argc != 3) {
		usage(argv[0]);
		goto done;
	}

	ssid = (unsigned char *) argv[1];
	ssid_len = strlen(argv[1]);
	passphrase = argv[2];

	err = crypto_psk_from_passphrase(passphrase, ssid, ssid_len, psk);
	if (err < 0) {
		printf("Unable to generate passphrase: %s\n", strerror(-err));
		goto done;
	}

	hexpsk = l_util_hexstring(psk, sizeof(psk));
	printf("PreSharedKey=%s\n", hexpsk);
	l_free(hexpsk);

	ret = EXIT_SUCCESS;

done:
	return ret;
}
