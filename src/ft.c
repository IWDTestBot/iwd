/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#include "src/ie.h"
#include "src/handshake.h"
#include "src/crypto.h"
#include "src/ft.h"
#include "src/mpdu.h"
#include "src/scan.h"
#include "src/frame-xchg.h"
#include "src/util.h"
#include "src/netdev.h"
#include "src/module.h"

static ft_tx_action_func_t tx_action = NULL;
static ft_tx_associate_func_t tx_assoc = NULL;
static struct l_queue *sm_list = NULL;

struct ft_info {
	uint8_t spa[6];
	uint8_t aa[6];
	uint8_t snonce[32];
	uint8_t mde[3];
	uint8_t *fte;
	uint8_t *authenticator_ie;
	uint32_t frequency;

	struct ie_ft_info ft_info;

	bool parsed : 1;
};

struct ft_info_finder {
	const uint8_t *spa;
	const uint8_t *aa;
};

struct ft_sm {
	struct handshake_state *hs;

	ft_authenticate_cb_t auth_cb;
	void *user_data;

	bool over_ds : 1;

	uint8_t prev_bssid[6];
	struct l_queue *ft_auths;
};

static bool match_ifindex(const void *a, const void *data)
{
	const struct ft_sm *sm = a;
	uint32_t ifindex = L_PTR_TO_UINT(data);

	return sm->hs->ifindex == ifindex;
}

static struct ft_sm *ft_sm_find(uint32_t ifindex)
{
	return l_queue_find(sm_list, match_ifindex, L_UINT_TO_PTR(ifindex));
}

/*
 * Calculate the MIC field of the FTE and write it directly to that FTE,
 * assuming it was all zeros before.  See 12.8.4 and 12.8.5.
 */
static bool ft_calculate_fte_mic(struct handshake_state *hs, uint8_t seq_num,
				const uint8_t *rsne, const uint8_t *fte,
				const uint8_t *ric, uint8_t *out_mic)
{
	struct iovec iov[10];
	int iov_elems = 0;
	struct l_checksum *checksum;
	const uint8_t *kck = handshake_state_get_kck(hs);
	size_t kck_len = handshake_state_get_kck_len(hs);
	uint8_t zero_mic[24] = {};

	iov[iov_elems].iov_base = hs->spa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = hs->aa;
	iov[iov_elems++].iov_len = 6;

	iov[iov_elems].iov_base = &seq_num;
	iov[iov_elems++].iov_len = 1;

	if (rsne) {
		iov[iov_elems].iov_base = (void *) rsne;
		iov[iov_elems++].iov_len = rsne[1] + 2;
	}

	iov[iov_elems].iov_base = hs->mde;
	iov[iov_elems++].iov_len = hs->mde[1] + 2;

	if (fte) {
		iov[iov_elems].iov_base = (void *) fte;
		iov[iov_elems++].iov_len = 4;

		iov[iov_elems].iov_base = zero_mic;
		iov[iov_elems++].iov_len = kck_len;

		iov[iov_elems].iov_base = (void *) (fte + 4 + kck_len);
		iov[iov_elems++].iov_len = fte[1] + 2 - 4 - kck_len;
	}

	if (ric) {
		iov[iov_elems].iov_base = (void *) ric;
		iov[iov_elems++].iov_len = ric[1] + 2;
	}

	if (kck_len == 16)
		checksum = l_checksum_new_cmac_aes(kck, kck_len);
	else
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA384, kck, kck_len);

	if (!checksum)
		return false;

	l_checksum_updatev(checksum, iov, iov_elems);
	l_checksum_get_digest(checksum, out_mic, kck_len);
	l_checksum_free(checksum);

	return true;
}

/*
 * Validate the FC, the addresses, Auth Type and authentication sequence
 * number of an FT Authentication Response frame, return status code, and
 * the start of the IE array (RSN, MD, FT, TI and RIC).
 * See 8.3.3.1 for the header and 8.3.3.11 for the body format.
 */
static bool ft_parse_authentication_resp_frame(const uint8_t *data, size_t len,
				const uint8_t *addr1, const uint8_t *addr2,
				const uint8_t *addr3, uint16_t auth_seq,
				uint16_t *out_status, const uint8_t **out_ies,
				size_t *out_ies_len)
{
	uint16_t status = 0;

	if (len < 30)
		return false;

	if (memcmp(data + 4, addr1, 6))
		return false;
	if (memcmp(data + 10, addr2, 6))
		return false;
	if (memcmp(data + 16, addr3, 6))
		return false;

	/* Check Authentication algorithm number is FT (2) */
	if (l_get_le16(data + 24) != 2)
		return false;

	if (l_get_le16(data + 26) != auth_seq)
		return false;

	if (auth_seq == 2 || auth_seq == 4)
		status = l_get_le16(data + 28);

	if (out_status)
		*out_status = status;

	if (status == 0 && out_ies) {
		*out_ies = data + 28;
		*out_ies_len = len - 28;
	}

	return true;
}

static bool ft_parse_associate_resp_frame(const uint8_t *frame, size_t frame_len,
				uint16_t *out_status, const uint8_t **rsne,
				const uint8_t **mde, const uint8_t **fte)
{
	const struct mmpdu_header *mpdu;
	const struct mmpdu_association_response *body;
	struct ie_tlv_iter iter;

	mpdu = mpdu_validate(frame, frame_len);
	if (!mpdu)
		return false;

	body = mmpdu_body(mpdu);

	ie_tlv_iter_init(&iter, body->ies, (const uint8_t *) mpdu + frame_len -
				body->ies);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (*rsne)
				return false;

			*rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (*mde)
				return false;

			*mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (*fte)
				return false;

			*fte = ie_tlv_iter_get_data(&iter) - 2;
			break;
		}
	}

	*out_status = L_LE16_TO_CPU(body->status_code);

	return true;
}

static int ft_tx_reassociate(struct ft_sm *ft)
{
	struct iovec iov[3];
	int iov_elems = 0;
	struct handshake_state *hs = ft->hs;
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	bool is_rsn = hs->supplicant_ie != NULL;
	uint8_t *rsne = NULL;

	if (is_rsn) {
		struct ie_rsn_info rsn_info;

		/*
		 * Rebuild the RSNE to include the PMKR1Name and append
		 * MDE + FTE.
		 *
		 * 12.8.4: "If present, the RSNE shall be set as follows:
		 * - Version field shall be set to 1.
		 * - PMKID Count field shall be set to 1.
		 * - PMKID field shall contain the PMKR1Name.
		 * - All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->supplicant_ie,
						hs->supplicant_ie[1] + 2,
						&rsn_info) < 0)
			goto error;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r1_name;

		rsne = alloca(256);
		ie_build_rsne(&rsn_info, rsne);

		iov[iov_elems].iov_base = rsne;
		iov[iov_elems].iov_len = rsne[1] + 2;
		iov_elems += 1;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	iov[iov_elems].iov_base = (void *) hs->mde;
	iov[iov_elems].iov_len = hs->mde[1] + 2;
	iov_elems += 1;

	if (is_rsn) {
		struct ie_ft_info ft_info;
		uint8_t *fte;

		/*
		 * 12.8.4: "If present, the FTE shall be set as follows:
		 * - ANonce, SNonce, R0KH-ID, and R1KH-ID shall be set to
		 *   the values contained in the second message of this
		 *   sequence.
		 * - The Element Count field of the MIC Control field shall
		 *   be set to the number of elements protected in this
		 *   frame (variable).
		 * [...]
		 * - All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		ft_info.mic_element_count = 3;
		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;
		memcpy(ft_info.r1khid, hs->r1khid, 6);
		ft_info.r1khid_present = true;
		memcpy(ft_info.anonce, hs->anonce, 32);
		memcpy(ft_info.snonce, hs->snonce, 32);

		fte = alloca(256);
		ie_build_fast_bss_transition(&ft_info, kck_len, fte);

		if (!ft_calculate_fte_mic(hs, 5, rsne, fte, NULL, ft_info.mic))
			goto error;

		/* Rebuild the FT IE now with the MIC included */
		ie_build_fast_bss_transition(&ft_info, kck_len, fte);

		iov[iov_elems].iov_base = fte;
		iov[iov_elems].iov_len = fte[1] + 2;
		iov_elems += 1;
	}

	return tx_assoc(ft->hs->ifindex, ft->prev_bssid, iov, iov_elems);

error:
	return -EINVAL;
}

static bool ft_verify_rsne(const uint8_t *rsne, const uint8_t *pmk_r0_name,
				const uint8_t *authenticator_ie)
{
	/*
	 * In an RSN, check for an RSNE containing the PMK-R0-Name and
	 * the remaining fields same as in the advertised RSNE.
	 *
	 * 12.8.3: "The RSNE shall be present only if dot11RSNAActivated
	 * is true. If present, the RSNE shall be set as follows:
	 * - Version field shall be set to 1.
	 * - PMKID Count field shall be set to 1.
	 * - PMKID List field shall be set to the value contained in the
	 *   first message of this sequence.
	 * - All other fields shall be identical to the contents of the
	 *   RSNE advertised by the AP in Beacon and Probe Response frames."
	 */

	struct ie_rsn_info msg2_rsne;

	if (!rsne)
		return false;

	if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg2_rsne) < 0)
		return false;

	if (msg2_rsne.num_pmkids != 1 ||
				memcmp(msg2_rsne.pmkids, pmk_r0_name, 16))
		return false;

	if (!handshake_util_ap_ie_matches(&msg2_rsne, authenticator_ie, false))
		return false;

	return true;
}

static int parse_ies(struct handshake_state *hs,
			const uint8_t *authenticator_ie,
			const uint8_t *ies, size_t ies_len,
			const uint8_t **mde_out,
			const uint8_t **fte_out)
{
	struct ie_tlv_iter iter;
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	bool is_rsn;

	ie_tlv_iter_init(&iter, ies, ies_len);

	while (ie_tlv_iter_next(&iter)) {
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_RSN:
			if (rsne)
				goto ft_error;

			rsne = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_MOBILITY_DOMAIN:
			if (mde)
				goto ft_error;

			mde = ie_tlv_iter_get_data(&iter) - 2;
			break;

		case IE_TYPE_FAST_BSS_TRANSITION:
			if (fte)
				goto ft_error;

			fte = ie_tlv_iter_get_data(&iter) - 2;
			break;
		}
	}

	is_rsn = hs->supplicant_ie != NULL;

	if (is_rsn) {
		if (!ft_verify_rsne(rsne, hs->pmk_r0_name, authenticator_ie))
			goto ft_error;
	} else if (rsne)
		goto ft_error;

	if (mde_out)
		*mde_out = mde;

	if (fte_out)
		*fte_out = fte;

	return 0;

ft_error:
	return -EINVAL;
}

static bool ft_parse_fte(struct handshake_state *hs,
				const uint8_t *snonce,
				const uint8_t *fte,
				struct ie_ft_info *ft_info)
{
	/*
	 * In an RSN, check for an FT IE with the same R0KH-ID and the same
	 * SNonce that we sent, and check that the R1KH-ID and the ANonce
	 * are present.  Use them to generate new PMK-R1, PMK-R1-Name and PTK
	 * in handshake.c.
	 *
	 * 12.8.3: "The FTE shall be present only if dot11RSNAActivated is
	 * true. If present, the FTE shall be set as follows:
	 * - R0KH-ID shall be identical to the R0KH-ID provided by the FTO
	 *   in the first message.
	 * - R1KH-ID shall be set to the R1KH-ID of the target AP, from
	 *   dot11FTR1KeyHolderID.
	 * - ANonce shall be set to a value chosen randomly by the target AP,
	 *   following the recommendations of 11.6.5.
	 * - SNonce shall be set to the value contained in the first message
	 *   of this sequence.
	 * - All other fields shall be set to 0."
	 */
	uint8_t zeros[24] = {};
	uint32_t kck_len = handshake_state_get_kck_len(hs);

	if (!fte)
		return false;

	if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
					kck_len, ft_info) < 0)
		return false;

	if (ft_info->mic_element_count != 0 ||
			memcmp(ft_info->mic, zeros, kck_len))
		return false;

	if (hs->r0khid_len != ft_info->r0khid_len ||
			memcmp(hs->r0khid, ft_info->r0khid,
				hs->r0khid_len) ||
			!ft_info->r1khid_present)
		return false;

	if (memcmp(ft_info->snonce, snonce, 32))
		return false;

	return true;
}

static bool mde_equal(const uint8_t *mde1, const uint8_t *mde2)
{
	if (!mde1 || !mde2)
		return false;

	/*
	 * Check for an MD IE identical to the one we sent in message 1
	 *
	 * 12.8.3: "The MDE shall contain the MDID and FT Capability and
	 * Policy fields. This element shall be the same as the MDE
	 * advertised by the target AP in Beacon and Probe Response frames."
	 */
	return memcmp(mde1, mde1, mde1[1] + 2) == 0;
}

static int ft_over_ds_parse_action_response(const uint8_t *frame,
					size_t frame_len,
					const uint8_t **spa_out,
					const uint8_t **aa_out,
					const uint8_t **ies_out,
					size_t *ies_len)
{
	uint16_t status;
	const uint8_t *aa;
	const uint8_t *spa;

	if (frame_len < 16)
		return -EINVAL;

	/* Category FT */
	if (frame[0] != 6)
		return -EINVAL;

	/* FT Action */
	if (frame[1] != 2)
		return -EINVAL;

	spa = frame + 2;
	aa = frame + 8;

	status = l_get_le16(frame + 14);
	if (status != 0)
		return (int)status;

	if (spa_out)
		*spa_out = spa;

	if (aa_out)
		*aa_out = aa;

	if (ies_out && ies_len) {
		*ies_out = frame + 16;
		*ies_len = frame_len - 16;
	}

	return 0;
}

int __ft_rx_associate(uint32_t ifindex, const uint8_t *frame, size_t frame_len)
{
	struct ft_sm *ft = ft_sm_find(ifindex);
	struct handshake_state *hs = ft->hs;
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	const uint8_t *rsne = NULL;
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	const uint8_t *sent_mde = hs->mde;
	bool is_rsn = hs->supplicant_ie != NULL;
	uint16_t out_status;

	if (!ft_parse_associate_resp_frame(frame, frame_len, &out_status, &rsne,
					&mde, &fte))
		return -EBADMSG;

	if (out_status != 0)
		return (int)out_status;

	/*
	 * During a transition in an RSN, check for an RSNE containing the
	 * PMK-R1-Name and the remaining fields same as in the advertised
	 * RSNE.
	 *
	 * 12.8.5: "The RSNE shall be present only if dot11RSNAActivated is
	 * true. If present, the RSNE shall be set as follows:
	 * - Version field shall be set to 1.
	 * - PMKID Count field shall be set to 1.
	 * - PMKID field shall contain the PMKR1Name
	 * - All other fields shall be identical to the contents of the RSNE
	 *   advertised by the target AP in Beacon and Probe Response frames."
	 */
	if (is_rsn) {
		struct ie_rsn_info msg4_rsne;

		if (!rsne)
			return -EBADMSG;

		if (ie_parse_rsne_from_data(rsne, rsne[1] + 2,
						&msg4_rsne) < 0)
			return -EBADMSG;

		if (msg4_rsne.num_pmkids != 1 ||
				memcmp(msg4_rsne.pmkids, hs->pmk_r1_name, 16))
			return -EBADMSG;

		if (!handshake_util_ap_ie_matches(&msg4_rsne,
							hs->authenticator_ie,
							false))
			return -EBADMSG;
	} else {
		if (rsne)
			return -EBADMSG;
	}

	/* An MD IE identical to the one we sent must be present */
	if (sent_mde && (!mde || memcmp(sent_mde, mde, sent_mde[1] + 2)))
		return -EBADMSG;

	/*
	 * An FT IE is required in an initial mobility domain
	 * association and re-associations in an RSN but not present
	 * in a non-RSN (12.4.2 vs. 12.4.3).
	 */
	if (sent_mde && is_rsn && !fte)
		return -EBADMSG;
	if (!(sent_mde && is_rsn) && fte)
		return -EBADMSG;

	if (fte) {
		struct ie_ft_info ft_info;
		uint8_t mic[24];

		if (ie_parse_fast_bss_transition_from_data(fte, fte[1] + 2,
						kck_len, &ft_info) < 0)
			return -EBADMSG;

		/*
		 * In an RSN, check for an FT IE with the same
		 * R0KH-ID, R1KH-ID, ANonce and SNonce that we
		 * received in message 2, MIC Element Count
		 * of 6 and the correct MIC.
		 */

		if (!ft_calculate_fte_mic(hs, 6, rsne, fte, NULL, mic))
			return -EBADMSG;

		if (ft_info.mic_element_count != 3 ||
				memcmp(ft_info.mic, mic, kck_len))
			return -EBADMSG;

		if (hs->r0khid_len != ft_info.r0khid_len ||
				memcmp(hs->r0khid, ft_info.r0khid,
					hs->r0khid_len) ||
				!ft_info.r1khid_present ||
				memcmp(hs->r1khid, ft_info.r1khid, 6))
			return -EBADMSG;

		if (memcmp(ft_info.anonce, hs->anonce, 32))
			return -EBADMSG;

		if (memcmp(ft_info.snonce, hs->snonce, 32))
			return -EBADMSG;

		if (ft_info.gtk_len) {
			uint8_t gtk[32];

			if (!handshake_decode_fte_key(hs, ft_info.gtk,
							ft_info.gtk_len,
							gtk))
				return -EBADMSG;

			if (ft_info.gtk_rsc[6] != 0x00 ||
					ft_info.gtk_rsc[7] != 0x00)
				return -EBADMSG;

			handshake_state_install_gtk(hs, ft_info.gtk_key_id,
							gtk, ft_info.gtk_len,
							ft_info.gtk_rsc, 6);
		}

		if (ft_info.igtk_len) {
			uint8_t igtk[16];

			if (!handshake_decode_fte_key(hs, ft_info.igtk,
						ft_info.igtk_len, igtk))
				return -EBADMSG;

			handshake_state_install_igtk(hs, ft_info.igtk_key_id,
						igtk, ft_info.igtk_len,
						ft_info.igtk_ipn);
		}

		handshake_state_install_ptk(ft->hs);
	}

	return 0;
}

static bool ft_build_authenticate_ies(struct handshake_state *hs,
				const uint8_t *new_snonce, uint8_t *buf,
				size_t *len)
{
	uint32_t kck_len = handshake_state_get_kck_len(hs);
	bool is_rsn = hs->supplicant_ie != NULL;
	uint8_t *ptr = buf;

	if (is_rsn) {
		struct ie_rsn_info rsn_info;

		/*
		 * Rebuild the RSNE to include the PMKR0Name and append
		 * MDE + FTE.
		 *
		 * 12.8.2: "If present, the RSNE shall be set as follows:
		 * - Version field shall be set to 1.
		 * - PMKID Count field shall be set to 1.
		 * - PMKID List field shall contain the PMKR0Name.
		 * - All other fields shall be as specified in 8.4.2.27
		 *   and 11.5.3."
		 */
		if (ie_parse_rsne_from_data(hs->supplicant_ie,
						hs->supplicant_ie[1] + 2,
						&rsn_info) < 0)
			return false;

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = hs->pmk_r0_name;

		ie_build_rsne(&rsn_info, ptr);
		ptr += ptr[1] + 2;
	}

	/* The MDE advertised by the BSS must be passed verbatim */
	ptr[0] = IE_TYPE_MOBILITY_DOMAIN;
	ptr[1] = 3;
	memcpy(ptr + 2, hs->mde + 2, 3);
	ptr += 5;

	if (is_rsn) {
		struct ie_ft_info ft_info;

		/*
		 * 12.8.2: "If present, the FTE shall be set as follows:
		 * - R0KH-ID shall be the value of R0KH-ID obtained by the
		 *   FTO during its FT initial mobility domain association
		 *   exchange.
		 * - SNonce shall be set to a value chosen randomly by the
		 *   FTO, following the recommendations of 11.6.5.
		 * - All other fields shall be set to 0."
		 */

		memset(&ft_info, 0, sizeof(ft_info));

		memcpy(ft_info.r0khid, hs->r0khid, hs->r0khid_len);
		ft_info.r0khid_len = hs->r0khid_len;

		memcpy(ft_info.snonce, new_snonce, 32);

		ie_build_fast_bss_transition(&ft_info, kck_len, ptr);

		ptr += ptr[1] + 2;
	}

	if (len)
		*len = ptr - buf;

	return true;
}

void __ft_set_tx_action_func(ft_tx_action_func_t func)
{
	tx_action = func;
}

void __ft_set_tx_associate_func(ft_tx_associate_func_t func)
{
	tx_assoc = func;
}

static bool match_ft_info(const void *a, const void *b)
{
	const struct ft_info *info = a;
	const struct ft_info_finder *finder = b;

	if (memcmp(info->spa, finder->spa, 6))
		return false;
	if (memcmp(info->aa, finder->aa, 6))
		return false;

	return true;
}

static bool ft_parse_ies(struct ft_info *info, struct handshake_state *hs,
			const uint8_t *ies, size_t ies_len)
{
	const uint8_t *mde = NULL;
	const uint8_t *fte = NULL;
	bool is_rsn = hs->supplicant_ie != NULL;

	if (parse_ies(hs, info->authenticator_ie, ies, ies_len,
				&mde, &fte) < 0)
		return false;

	if (!mde_equal(info->mde, mde))
		goto ft_error;

	if (is_rsn) {
		if (!ft_parse_fte(hs, info->snonce, fte, &info->ft_info))
			goto ft_error;

		info->fte = l_memdup(fte, fte[1] + 2);
	} else if (fte)
		goto ft_error;

	return true;

ft_error:
	return false;
}

static void ft_action_response_cb(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct ft_sm *sm = user_data;
	struct ft_info *info;
	int ret;
	const uint8_t *aa;
	const uint8_t *spa;
	const uint8_t *ies;
	size_t ies_len;
	struct ft_info_finder finder;

	ret = ft_over_ds_parse_action_response(body, body_len, &spa, &aa,
						&ies, &ies_len);
	if (ret != 0)
		return;

	finder.spa = spa;
	finder.aa = aa;

	info = l_queue_find(sm->ft_auths, match_ft_info, &finder);
	if (!info)
		return;

	if (!ft_parse_ies(info, sm->hs, ies, ies_len))
		goto ft_error;

	info->parsed = true;

	return;

ft_error:
	l_debug("FT-over-DS authenticate to "MAC" failed", MAC_STR(info->aa));
}

static struct ft_info *ft_info_new(struct handshake_state *hs,
					const struct scan_bss *target_bss)
{
	struct ft_info *info = l_new(struct ft_info, 1);

	memcpy(info->spa, hs->spa, 6);
	memcpy(info->aa, target_bss->addr, 6);
	memcpy(info->mde, target_bss->mde, sizeof(info->mde));

	info->frequency = target_bss->frequency;

	if (target_bss->rsne)
		info->authenticator_ie = l_memdup(target_bss->rsne,
						target_bss->rsne[1] + 2);

	l_getrandom(info->snonce, 32);

	return info;
}

static void ft_info_destroy(void *data)
{
	struct ft_info *info = data;

	if (info->fte)
		l_free(info->fte);

	if (info->authenticator_ie)
		l_free(info->authenticator_ie);

	l_free(info);
}

static void ft_prepare_handshake(struct ft_info *info,
					struct handshake_state *hs)
{
	if (!hs->supplicant_ie)
		return;

	if (info->authenticator_ie)
		handshake_state_set_authenticator_ie(hs,
						info->authenticator_ie);

	memcpy(hs->mde + 2, info->mde, 3);

	memcpy(hs->snonce, info->snonce, sizeof(hs->snonce));

	handshake_state_set_fte(hs, info->fte);

	handshake_state_set_anonce(hs, info->ft_info.anonce);

	handshake_state_set_kh_ids(hs, info->ft_info.r0khid,
						info->ft_info.r0khid_len,
						info->ft_info.r1khid);

	handshake_state_derive_ptk(hs);
}

static const uint8_t action_ft_response_prefix[] =  { 0x06, 0x02 };

struct ft_sm *ft_sm_new(struct handshake_state *hs)
{
	struct ft_sm *sm = l_new(struct ft_sm, 1);
	struct netdev *netdev = netdev_find(hs->ifindex);

	sm->hs = hs;
	sm->ft_auths = l_queue_new();
	sm->over_ds = hs->mde[4] & 1;
	memcpy(sm->prev_bssid, hs->aa, 6);

	if (sm->over_ds)
		frame_watch_add(netdev_get_wdev_id(netdev), FRAME_GROUP_FT,
			0x00d0, action_ft_response_prefix,
			sizeof(action_ft_response_prefix),
			ft_action_response_cb, sm, NULL);

	l_queue_push_tail(sm_list, sm);

	return sm;
}

void ft_sm_free(struct ft_sm *sm)
{
	struct netdev *netdev = netdev_find(sm->hs->ifindex);

	if (sm->over_ds)
		frame_watch_group_remove(netdev_get_wdev_id(netdev),
					FRAME_GROUP_FT);

	l_queue_destroy(sm->ft_auths, ft_info_destroy);

	l_queue_remove(sm_list, sm);

	l_free(sm);
}

int ft_action(struct ft_sm *sm, const struct scan_bss *target)
{
	struct ft_info *info;
	uint8_t ft_req[14];
	struct iovec iov[5];
	uint8_t ies[512];
	size_t len;
	int ret = -EINVAL;

	info = ft_info_new(sm->hs, target);

	ft_req[0] = 6; /* FT category */
	ft_req[1] = 1; /* FT Request action */
	memcpy(ft_req + 2, info->spa, 6);
	memcpy(ft_req + 8, info->aa, 6);

	if (!ft_build_authenticate_ies(sm->hs, info->snonce, ies, &len))
		goto failed;

	iov[0].iov_base = ft_req;
	iov[0].iov_len = sizeof(ft_req);

	iov[1].iov_base = ies;
	iov[1].iov_len = len;

	ret = tx_action(sm->hs->ifindex, sm->hs->aa, iov, 2);
	if (ret < 0)
		goto failed;

	l_queue_push_tail(sm->ft_auths, info);

	return 0;

failed:
	l_free(info);
	return ret;
}

static void ft_authenticate_cb(int err, void *user_data)
{
	if (err < 0)
		l_debug("Failed to send FT-Authenticate");
}

static void ft_authenticate_destroy(void *user_data)
{
	struct ft_sm *sm = user_data;
	struct ft_info *info = l_queue_peek_head(sm->ft_auths);

	if (L_WARN_ON(!info))
		return;

	if (!info->parsed)
		goto failed;

	sm->auth_cb(0, info->aa, info->frequency, sm->user_data);

	return;

failed:
	l_queue_pop_head(sm->ft_auths);
	ft_info_destroy(info);

	sm->auth_cb(-EINVAL, info->aa, info->frequency, sm->user_data);
}

static void ft_authenticate_response_cb(const struct mmpdu_header *hdr,
					const void *body, size_t body_len,
					int rssi, void *user_data)
{
	struct ft_sm *sm = user_data;
	struct ft_info *info = l_queue_peek_head(sm->ft_auths);
	uint16_t status;
	const uint8_t *ies;
	size_t ies_len;

	if (!ft_parse_authentication_resp_frame((const uint8_t *)hdr,
					mmpdu_header_len(hdr) + body_len,
					info->spa, info->aa, info->aa, 2,
					&status, &ies, &ies_len))
		return;

	if (status != 0)
		return;

	if (!ft_parse_ies(info, sm->hs, ies, ies_len))
		return;

	info->parsed = true;

	return;
}

static const struct frame_xchg_prefix ft_prefix = {
	.frame_type = 0x0000 | (MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION << 4),
	.data = (uint8_t []) { 0x02, 0x00 },
	.len = 2,
};

static bool ft_send_authenticate(struct ft_sm *sm, struct ft_info *info)
{
	uint64_t wdev_id = netdev_get_wdev_id(netdev_find(sm->hs->ifindex));
	uint8_t header[28 + sizeof(struct mmpdu_authentication)];
	uint8_t ies[256];
	size_t len;
	struct iovec iov[3];
	struct mmpdu_header *mpdu = (struct mmpdu_header *) header;
	struct mmpdu_authentication *auth;
	struct handshake_state *hs = sm->hs;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION;
	memcpy(mpdu->address_1, info->aa, 6);
	memcpy(mpdu->address_2, info->spa, 6);
	memcpy(mpdu->address_3, info->aa, 6);

	/* Authentication body */
	auth = (void *) mmpdu_body(mpdu);
	auth->algorithm = L_CPU_TO_LE16(MMPDU_AUTH_ALGO_FT);
	auth->transaction_sequence = L_CPU_TO_LE16(1);
	auth->status = L_CPU_TO_LE16(0);

	iov[0].iov_base = mpdu;
	iov[0].iov_len = mmpdu_header_len(mpdu) +
				sizeof(struct mmpdu_authentication);

	if (!ft_build_authenticate_ies(hs, info->snonce, ies, &len))
		return false;

	iov[1].iov_base = ies;
	iov[1].iov_len = len;

	iov[2].iov_base = NULL;

	return frame_xchg_start(wdev_id, iov, info->frequency, FRAME_GROUP_FT,
				100, 0, 0,
				ft_authenticate_cb, sm,
				ft_authenticate_destroy, &ft_prefix,
				ft_authenticate_response_cb, NULL) != 0;
}

int ft_authenticate(struct ft_sm *sm, const struct scan_bss *target,
			ft_authenticate_cb_t cb, void *user_data)
{
	struct ft_info *info = ft_info_new(sm->hs, target);
	int ret = -EINVAL;

	if (!ft_send_authenticate(sm, info))
		goto failed;

	sm->auth_cb = cb;
	sm->user_data = user_data;

	l_queue_push_tail(sm->ft_auths, info);

	return 0;

failed:
	l_free(info);
	return ret;
}

int ft_associate(struct ft_sm *sm, const uint8_t *addr)
{
	struct ft_info *info;
	struct ft_info_finder finder;

	finder.spa = sm->hs->spa;
	finder.aa = addr;

	info = l_queue_find(sm->ft_auths, match_ft_info, &finder);
	/*
	 * TODO: Since FT-over-DS is done early, before the time of roaming, it
	 *       may end up that a completely new BSS is the best candidate and
	 *       we haven't yet authenticated. We could actually authenticate
	 *       at this point, but for now just assume the caller will choose
	 *       a different BSS.
	 */
	if (!info)
		return -ENOENT;

	ft_prepare_handshake(info, sm->hs);

	return ft_tx_reassociate(sm);
}

static int ft_init(void)
{
	sm_list = l_queue_new();

	return 0;
}

static void ft_exit(void)
{
	if (!l_queue_isempty(sm_list))
		l_warn("stale FT state machines found!");

	l_queue_destroy(sm_list, (l_queue_destroy_func_t)ft_sm_free);
}

IWD_MODULE(ft, ft_init, ft_exit);
