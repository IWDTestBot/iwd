/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

struct metadata {
	uint64_t timestamp;
	uint16_t len;
	uint16_t protocol;
} __attribute__ ((packed));

#endif /* __BOOTSTRAP_H */
