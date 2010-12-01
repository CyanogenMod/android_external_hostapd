/*
 * hostapd / Module short description
 * Copyright (c) 2010, Texas Instruments, Inc. - http://www.ti.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * For more details please review the below BSD terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name(s) of the above-listed copyright holder(s) nor the
 *  names of its contributors may be used to endorse or promote products
 *  derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file driver_wilink.c
 *  \brief hostapd interface to WiLink driver
 *
 *  \see driver.h
 */

#include "includes.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "wireless_copy.h"
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>

#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "hw_features.h"
#include "mlme.h"
#include "l2_packet/l2_packet.h"
#include "utils/common.h"
#include "APExternalIf.h"
#include "privateCmd.h"
#include "common.h"
#include "wpa.h"
#include "wpa_auth_i.h"
#include "regulatory.h"

#include <signal.h>
#ifndef ANDROID
#include <execinfo.h>
#endif


#define WILINK_CTRL_HDR_GET_STATUS(c) ((c) & 0x07)

struct wilink_driver_data {
	struct hostapd_data *hapd;

	char iface[IFNAMSIZ + 1];
	int cmd_sock;   /* socket for wext commands   */
	int event_sock; /* socket for wireless events */

	struct l2_packet_data *eapol_l2;  /* socket for EAPOL frames    */
	struct l2_packet_data  *mlme_l2;  /* socket for monitor         */

    TApChanHwInfo     *pRegDomain;
    RegDomainStruct_t *pRegDomainHandle;

	int we_version;

	int dtim_int;
	int beacon_int;
};


void wilink_rx_eapol(void *ctx, const u8 *src_addr, const u8 *buf, size_t len) {
	struct wilink_driver_data *drv = ctx;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: received EAPOL with len %d from " MACSTR, __func__, 
			(int) len, MAC2STR(src_addr));
	ieee802_1x_receive(drv->hapd, src_addr, buf, len);
}


static void wilink_tx_callback(struct hostapd_data *hapd, u8 *buf, size_t len,
		int ok)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: TX complete: %s", __func__, ok ? "OK" : "NOT OK");

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		wpa_printf(MSG_DEBUG, "HAPDTI %s: MGMT (TX callback) %s", __func__, ok ? "ACK" : "fail");
		ieee802_11_mgmt_cb(hapd, buf, len, stype, ok);
		break;
	default:
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: unknown TX callback frame type %d stype %d", 
				__func__, type, stype);
		break;
	}
}


static void wilink_rx_mgmt(void *ctx, const u8 *src_addr, const u8 *data, size_t len) {
	struct wilink_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	size_t data_len = len;
	u8* buf;
	struct sta_info *sta;
	struct hostapd_frame_info fi;


	len -=  sizeof(TApFrameHeader);
	buf = ((u8*) data) + sizeof(TApFrameHeader);
	/* 'len' and 'buf' now refer to the actual frame less the WILINK hdr */

	wpa_printf(MSG_DEBUG, "%s: received MGMT with len %d from " MACSTR, __func__,
			(int) len, MAC2STR(src_addr));
	wpa_hexdump(MSG_DEBUG, "MGMT", data, data_len);
    wpa_printf(MSG_DEBUG,"\n");

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

    if (type != WLAN_FC_TYPE_MGMT) {
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: frame is not mgmt frame", __func__);
		return;
	}

	switch (((TApFrameHeader*)data)->sCtrlHdr) { 
	case AP_CTRL_HDR_RX:
		wpa_printf(MSG_DEBUG, "HAPDTI %s: processing management frame", __func__);
		memset(&fi, 0, sizeof(struct hostapd_frame_info));
		fi.phytype = 7;
		ieee802_11_mgmt(hapd, buf, len, stype, &fi);
		break;
    case AP_CTRL_HDR_TX_SUCCESS: 		/* successful TX Complete event */
        wpa_printf(MSG_DEBUG, "HAPDTI %s: GET TX SUCCSESS", __func__);
		wilink_tx_callback(hapd, buf, len, 1);
		return;
    case AP_CTRL_HDR_TX_FAIL: 			/* fail TX Complete event */
        wpa_printf(MSG_DEBUG, "HAPDTI %s: GET TX FAIL", __func__);
		wilink_tx_callback(hapd, buf, len, 0);
		return;
	}

    sta = ap_get_sta(hapd,  hdr->addr2);
    if (!sta) {
        wpa_printf(MSG_ERROR,"station is not found" MACSTR, MAC2STR(hdr->addr2));
    }
    else {
        sta->flags |= WLAN_STA_AUTH;
    }


}

#ifndef ANDROID
void handler(int sig) {
	void *array[10];
	size_t size;

	size = backtrace(array, 10);

	fprintf(stderr, "Error: signal %d:\n", sig);
	backtrace_symbols_fd(array, size, 2);
	exit(1);
}
#endif

static int wilink_get_we_version(struct wilink_driver_data *drv)
{
	struct iw_range *range;
	struct iwreq iwr;
	int minlen;
	size_t buflen;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

	drv->we_version = 0;

	/*
	 * Use larger buffer than struct iw_range in order to allow the
	 * structure to grow in the future.
	 */
	buflen = sizeof(struct iw_range) + 500;
	range = os_zalloc(buflen);
	if (range == NULL)
		return -1;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) range;
	iwr.u.data.length = buflen;

	minlen = ((char *) &range->enc_capa) - (char *) range +
	sizeof(range->enc_capa);

	if (ioctl(drv->cmd_sock, SIOCGIWRANGE, &iwr) < 0) {
		perror("ioctl[SIOCGIWRANGE]");
		free(range);
		return -1;
	} else if (iwr.u.data.length >= minlen &&
			range->we_version_compiled >= 18) {
		wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
				"WE(source)=%d enc_capa=0x%x",
				range->we_version_compiled,
				range->we_version_source,
				range->enc_capa);
		drv->we_version = range->we_version_compiled;
	}

	free(range);
	return 0;
}

static void wilink_wireless_event_wireless_custom(struct wilink_driver_data *drv, char *buf) 
{
	TApEvent *pApEvent  = (TApEvent *) buf;
    unsigned char *pAdr = pApEvent->uAddr;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: event=%u from sta=" MACSTR, __func__, pApEvent->uEvent, MAC2STR(pAdr));

    switch (pApEvent->uEvent) {

    case AP_EVENT_STA_AGING:
        wpa_printf(MSG_DEBUG, "HAPDTI %s: STA Aging Event, disconnecting STA", __func__);
        hostapd_wpa_auth_disconnect(drv->hapd, pApEvent->uAddr, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY);
        break;

    case AP_EVENT_STA_MIC_FAILURE:
		wpa_printf(MSG_DEBUG, "HAPDTI %s: STA MICFAILURE Event", __func__);
		ieee80211_michael_mic_failure(drv->hapd, (const u8*) pAdr, 1);
		break;

    case AP_EVENT_STA_MAX_TX_RETRY:
        wpa_printf(MSG_DEBUG, "HAPDTI %s: STA Max Retry event, disconnecting STA", __func__);
        hostapd_wpa_auth_disconnect(drv->hapd, pApEvent->uAddr, WLAN_REASON_UNSPECIFIED);
        break;

	case AP_EVENT_DRV_RESET:
		{
			char *config_fname;
			wpa_printf(MSG_DEBUG, "HAPDTI %s: DRV_RESET event", __func__);
			/*save config file name before it is freed in deinit*/
			config_fname = os_strdup(drv->hapd->iface->config_fname);
			if (!config_fname)
				return ;
			hostapd_reset_iface(drv->hapd->iface, config_fname, 0/*don't send deauth*/);
			os_free(config_fname);
		}
		break;
	default:
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: unsupported custom event %u", __func__, pApEvent->uEvent);
	}
}


static void wilink_wireless_event_wireless(struct wilink_driver_data *drv,
		char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom;
	
	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		wpa_printf(MSG_DEBUG, "Wireless event: cmd=0x%x len=%d",
				iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
				(iwe->cmd == IWEVMICHAELMICFAILURE ||
						iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
					sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
		
			wilink_wireless_event_wireless_custom(drv, custom);

			break;
		}

		pos += iwe->len;
	}
}




static void wilink_wireless_event_rtm_newlink(struct wilink_driver_data *drv,
		struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr *attr;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);
	
	if (len < (int) sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	/* TODO: use ifi->ifi_index to filter out wireless events from other
	 * interfaces */

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			wilink_wireless_event_wireless(
					drv, ((char *) attr) + rta_len,
					attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}



static void wilink_wireless_event_receive(int sock, void *eloop_ctx,
		void *sock_ctx)
{
	char buf[256];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	struct wilink_driver_data *drv = eloop_ctx;
	
	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (left >= (int) sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			wpa_printf(MSG_ERROR, "%s: Malformed netlink message: len=%d left=%d plen=%d\n", __func__, len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			wilink_wireless_event_rtm_newlink(drv, h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		wpa_printf(MSG_ERROR, "%s: %d extra bytes in the end of netlink message\n", __func__, left);
	}
}




static int wilink_wireless_event_init(void *priv)
{
	struct wilink_driver_data *drv = priv;
	int s;
	struct sockaddr_nl local;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

	wilink_get_we_version(drv);

	drv->event_sock = -1;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		return -1;
	}

	eloop_register_read_sock(s, wilink_wireless_event_receive, drv,
			NULL);
	drv->event_sock = s;

	return 0;
}



static void wilink_wireless_event_deinit(void *priv) {
	struct wilink_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);
	if (drv->event_sock < 0)
		return;
	eloop_unregister_read_sock(drv->event_sock);
	close(drv->event_sock);
}


static int wilink_send_mgmt_frame(void *priv, const void *data, size_t len,
		int flags) {
	struct wilink_driver_data *drv = priv;
	const struct ieee80211_mgmt *mgmt = data;

	wpa_printf(MSG_DEBUG, " HAPDTI %s: sending %d byte MGMT frame to " MACSTR, __func__,
			(int) len, MAC2STR(mgmt->da));
	wpa_hexdump(MSG_DEBUG, "MGMT", data, len);
    wpa_printf(MSG_DEBUG,"\n");
   
    return (l2_packet_send(drv->mlme_l2, mgmt->da, AP_MGMT_ETH_TYPE, data, len) < 0);
}


static int wilink_sta_disassoc(void *priv, const u8 *addr, int reason)
{
	struct wilink_driver_data *drv = priv;
	struct ieee80211_mgmt mgmt;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
			WLAN_FC_STYPE_DISASSOC);
	memcpy(mgmt.da, addr, ETH_ALEN);
	memcpy(mgmt.sa, drv->hapd->own_addr, ETH_ALEN);
	memcpy(mgmt.bssid, drv->hapd->own_addr, ETH_ALEN);
	mgmt.u.disassoc.reason_code = host_to_le16(reason);
	return  wilink_send_mgmt_frame(drv, &mgmt, IEEE80211_HDRLEN +
			sizeof(mgmt.u.disassoc), 0);
}

static int wilink_send_eapol(void *priv, const u8 *addr, const u8 *data,
		size_t data_len, int encrypt, const u8 *own_addr)
{
	struct wilink_driver_data *drv = priv;
	
	wpa_printf(MSG_DEBUG, "HAPDTI %s: sending %d byte EAPOL packet to " MACSTR,	__func__,
			(int) data_len, MAC2STR(addr));
	
	return (l2_packet_send(drv->eapol_l2, addr, ETH_P_EAPOL, data, data_len) < 0);	
}

/* ****************************** PRIVATE COMMANDS ******************** */

static int wilink_send_ti_private_cmd(struct wilink_driver_data *drv, int OpCode, char *buffer, int len)
{
	struct iwreq iwr;
	ti_private_cmd_t private_cmd;

    private_cmd.cmd = OpCode;

    if (OpCode & SET_BIT) 
	{
		private_cmd.flags = PRIVATE_CMD_SET_FLAG;
		private_cmd.in_buffer = buffer;
		private_cmd.in_buffer_len = len;
		private_cmd.out_buffer = NULL;
		private_cmd.out_buffer_len = 0;
	}
	if (OpCode & GET_BIT)
	{
		private_cmd.flags = PRIVATE_CMD_GET_FLAG;
		private_cmd.out_buffer = buffer;
		private_cmd.out_buffer_len = len;
		private_cmd.in_buffer = buffer;
		private_cmd.in_buffer_len = len;
	}

	os_memset(&iwr, 0, sizeof(iwr));
	os_strncpy(iwr.ifr_name, drv->iface, IFNAMSIZ);	

	iwr.u.data.pointer = &private_cmd;
	iwr.u.data.length = sizeof(ti_private_cmd_t);
	iwr.u.data.flags = 0;	

	if (ioctl(drv->cmd_sock, SIOCIWAPPRIV, &iwr) < 0) 
	{
		perror("ioctl[SIOCIWFIRSTPRIV+2]");
		return -1;
	}

	return 0;

}

static void *wilink_init(struct hostapd_data *hapd)
{
	struct wilink_driver_data *drv;
	int ret;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);

#ifndef ANDROID
	signal(SIGSEGV, handler);	
#endif

	drv = os_zalloc(sizeof(struct wilink_driver_data));
	if (drv == NULL) {
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: Could not allocate memory for wilink driver data", __func__);
		return NULL;
	}

	drv->hapd = hapd;
    
   if (hapd->conf == NULL) 
        wpa_printf(MSG_ERROR,"HAPDTIERR %s: hapd->conf null \n", __func__);
    else
       memcpy(drv->iface, hapd->conf->iface, sizeof(drv->iface));

	/* init cmd_sock */
	drv->cmd_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->cmd_sock < 0) {
		perror("socket(PF_INET,SOCK_DGRAM)");
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: error creating cmd_sock", __func__);
		goto failed;
	}

	/* init l2 sockets */
	drv->eapol_l2 = l2_packet_init(drv->iface,
			NULL,
			ETH_P_EAPOL,
			wilink_rx_eapol, drv, 0);

    drv->mlme_l2 = l2_packet_init(drv->iface,
			NULL,
			AP_MGMT_ETH_TYPE,
			wilink_rx_mgmt, drv, 0);
   
    if (!drv->eapol_l2 || !drv->mlme_l2) {
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: error creating l2 sockets", __func__);
		goto failed;
	}

    if (l2_packet_get_own_addr(drv->eapol_l2, hapd->own_addr))
    {
        wpa_printf(MSG_ERROR, "HAPDTIERR %s: cannot retrieve own hwdr addr", __func__);
        goto failed;
    }

    drv->pRegDomain = (TApChanHwInfo *) os_zalloc(sizeof(TApChanHwInfo));
	if (drv->pRegDomain == NULL) {
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: Could not allocate memory for RegDomain", __func__);
        goto failed;
	}
    drv->pRegDomainHandle = regulatory_create();
    if (drv->pRegDomainHandle == NULL) {
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: Could not allocate memory for RegDomain", __func__);
        goto failed;
	}

	ret  = wilink_send_ti_private_cmd(drv, ROLE_AP_ENABLE, NULL, 0);
	if (ret){
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: error sending ENABLE command to the driver", __func__);
		goto failed;
	}

	return drv;

failed:
    wpa_printf(MSG_ERROR, "HAPDTIERR %s: failed", __func__);

	/* Free of allocated resources will be performed in driver deinit() callback which shall 
	be called when init() returns NULL*/
	if (drv->cmd_sock > 0)
		close(drv->cmd_sock);
	if (drv->eapol_l2)
		l2_packet_deinit(drv->eapol_l2);
	if (drv->mlme_l2)
		l2_packet_deinit(drv->mlme_l2);
    if (drv->pRegDomain)
        free(drv->pRegDomain);
    regulatory_destroy(drv->pRegDomainHandle);
    free(drv);
	return NULL;
}

static void wilink_deinit(void *priv) {
	struct wilink_driver_data *drv = priv;
	int    ret;

	wpa_printf(MSG_DEBUG, "HAPDTI %s: enter",__func__);

	ret  = wilink_send_ti_private_cmd(drv, ROLE_AP_STOP, NULL, 0);
	if (ret)
		wpa_printf(MSG_ERROR, "HAPDTIERR %s: error sending STOP command to the driver", __func__);
	

    if (drv->cmd_sock > 0)
		close(drv->cmd_sock);
	if (drv->eapol_l2)
		l2_packet_deinit(drv->eapol_l2);
	if (drv->mlme_l2)
		l2_packet_deinit(drv->mlme_l2);
    if(drv->pRegDomain)
		free(drv->pRegDomain);

	regulatory_destroy(drv->pRegDomainHandle);
	if(drv)
		free(drv);
}

static int wilink_sta_deauth(void *priv, const u8 *addr, int reason)
{
	struct wilink_driver_data *drv = priv;
	int	   broadcast;

    wpa_printf(MSG_DEBUG, "HAPDTI %s: enter", __func__);
	broadcast = (memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0);
	if (!broadcast)
	{
		TApGeneralParam deauthParams;

		memcpy(deauthParams.cMac, addr, AP_MAC_ADDR);
		deauthParams.lValue = reason;

		return  wilink_send_ti_private_cmd(drv, ROLE_AP_DEAUTH_STATION, (char*)&deauthParams,sizeof(deauthParams));
	}
	else
	{
		struct ieee80211_mgmt mgmt;

		memset(&mgmt, 0, sizeof(mgmt));
		mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
				WLAN_FC_STYPE_DEAUTH);
		memcpy(mgmt.da, addr, ETH_ALEN);
		memcpy(mgmt.sa, drv->hapd->own_addr, ETH_ALEN);
		memcpy(mgmt.bssid, drv->hapd->own_addr, ETH_ALEN);
		mgmt.u.deauth.reason_code = host_to_le16(reason);
		return wilink_send_mgmt_frame(drv, &mgmt, IEEE80211_HDRLEN +
				sizeof(mgmt.u.deauth), 0);
	}
}


static int wilink_set_country(void *priv, const char *country)
{
	struct wilink_driver_data *drv = priv;
	int ret = 0;

	if (country)
	{
		strcpy(drv->pRegDomain->cCountry, country);
	}
	/* build hw capability table */
	ret = wilink_send_ti_private_cmd(drv,ROLE_AP_GET_HW, (char*)drv->pRegDomain, sizeof(*drv->pRegDomain));
	regulatory_build_hw_capability(drv->pRegDomainHandle,drv->pRegDomain,drv->hapd->iconf->channel,drv->hapd->iconf->hw_mode);
        
	return ret;
}


static int wilink_set_rts(void *priv, int rts)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

	GenStruct.lValue = rts;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_RTS,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}

static int wilink_set_broadcast_ssid(void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

	GenStruct.lValue = (value == 1) ? AP_SSID_TYPE_HIDDEN : AP_SSID_TYPE_PUBLIC;
	ret  = wilink_send_ti_private_cmd(drv, ROLE_AP_SET_SSID_TYPE, (char*)&GenStruct,sizeof(GenStruct));
	return ret;
}

static int wilink_set_cts_protect(void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = value;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_USE_CTS_PROT,(char*)&GenStruct,sizeof(GenStruct));
	return ret;

}


static int wilink_set_dtim_period(const char *iface, void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = value;
    drv->dtim_int = value;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_DTIM_PERIOD,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}



static int wilink_set_privacy(const char *ifname, void *priv, int enabled)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = enabled;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_PRIVACY,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}



static int wilink_sta_set_flags(void *priv, const u8 *addr,
		int total_flags, int flags_or, int flags_and)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    if (addr == NULL) 
        return ret;
    
    memcpy(GenStruct.cMac,addr,AP_MAC_ADDR);
	if (flags_or & WLAN_STA_AUTHORIZED)
		GenStruct.lValue = 1;
	if (!(flags_and & WLAN_STA_AUTHORIZED))
		GenStruct.lValue = 0;

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_PORT_STATUS,(char*)&GenStruct,sizeof(GenStruct));
	if (ret) 
		return ret;

	if (flags_or & WLAN_STA_WME)
		GenStruct.lValue = 1;
	if (!(flags_and & WLAN_STA_WME))
		GenStruct.lValue = 0;

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_STA_WME,(char*)&GenStruct,sizeof(GenStruct));
	if (ret) 
		return ret;

	if (flags_or & WLAN_STA_SHORT_PREAMBLE)
		GenStruct.lValue = 1;
	if (!(flags_and & WLAN_STA_SHORT_PREAMBLE))
		GenStruct.lValue = 0;

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_STA_SHORT_PREAMBLE,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}


static int wilink_set_tx_queue_params(void *priv, int queue, int aifs,
		int cw_min, int cw_max, int burst_time)
{
	struct wilink_driver_data *drv = priv;
	TApTxParams TxParamStruct;
	int ret = 0;

    TxParamStruct.cQueueId = queue;
	TxParamStruct.cAifs = aifs;
	TxParamStruct.sCwmin = cw_min;
	TxParamStruct.sCwmax = cw_max;
	TxParamStruct.sTxop = burst_time;

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_TX_PARAM,(char*)&TxParamStruct,sizeof(TxParamStruct));
	return ret;

}


static int wilink_set_short_slot_time(void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = value;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_USE_SHORT_SLOT_TIME,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}

static int wilink_set_preamble(void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = value;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_AP_SHORT_PREAMBLE,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}

static int wilink_set_beacon_int(void *priv, int value)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam GenStruct;
	int ret = 0;

    GenStruct.lValue = value;
	drv->beacon_int = value;
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_BEACON_INT,(char*)&GenStruct,sizeof(GenStruct));
	return ret;
}


static int wilink_set_rate_sets(void *priv, int *supp_rates, int *basic_rates,
		int mode)
{
	struct wilink_driver_data *drv = priv;
	TApRateSet  RateParams;
	int ret = 0;
	int i;

	memset(&RateParams, 0, sizeof(RateParams));

	RateParams.cMode = mode;

	if ((supp_rates != NULL) || (basic_rates != NULL))
	{
		if (supp_rates != NULL)
		{
		  for (i=0; (i<AP_MAX_SUPPORT_RATE) ;i++)
		  {
		    if (supp_rates[i]>0)        
			 RateParams.aSupportedRates[i] = supp_rates[i];
		  }
		  RateParams.cSuppRateLen = i;
		}
	
		if (basic_rates != NULL)
		{
		  for (i=0; (i<AP_MAX_SUPPORT_RATE && basic_rates[i]>0) ;i++)
		  {
			 RateParams.aBasicRates[i] = basic_rates[i];
		  }
		  RateParams.cBasicRateLen = i;
		}
	
		ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_RATE,(char*)&RateParams,sizeof(RateParams));
    }

	return ret;

}

static int wilink_read_sta_data(void *priv, struct hostap_sta_driver_data *data,
		const u8 *addr)
{
	struct wilink_driver_data *drv = priv;
	TApStationInfo staDataStruct;
	int ret = 0;

    memcpy(staDataStruct.cMac,addr,AP_MAC_ADDR);
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_GET_STATION_PARAM,(char*)&staDataStruct,sizeof(staDataStruct));
	if(ret == 0)
	{
		data->rx_bytes = staDataStruct.iRxBytes;
		data->tx_bytes = staDataStruct.iTxBytes;
		data->inactive_msec = staDataStruct.iInactiveTime;
	}

	return ret;
}

static int wilink_sta_add2(const char *ifname, void *priv,
		struct hostapd_sta_add_params *params)
{
	struct wilink_driver_data *drv = priv;
	TApStationParams addStaParams;
	int ret = 0;

    if (params == NULL)
       return ret;
    
	memcpy(addStaParams.cMac,params->addr,AP_MAC_ADDR);
    /* Check station supported length */
    if( params->supp_rates_len > AP_MAX_SUPPORT_RATE )
    {
        wpa_printf(MSG_ERROR, "%s: Max supported rates %d from " MACSTR, __func__,
            (int) params->supp_rates_len, MAC2STR(params->addr));

        /*  Update supported rates according to the AP_MAX_SUPPORT_RATE */
        params->supp_rates_len = AP_MAX_SUPPORT_RATE;

    }
	memcpy(addStaParams.cSupportedRates ,params->supp_rates,params->supp_rates_len);

	addStaParams.cSupportedRatesLen = params->supp_rates_len;
	addStaParams.ilistenInterval = params->listen_interval;
	addStaParams.sAid = params->aid;
	addStaParams.sCapability = params->capability;
    addStaParams.iFlag = params->flags;

	wpa_printf(MSG_DEBUG, "%s: "MACSTR, __func__,MAC2STR(params->addr));
	wpa_printf(MSG_DEBUG, "%s: addStaParams.ilistenInterval=%u\n",__func__,addStaParams.ilistenInterval);
	wpa_printf(MSG_DEBUG, "%s: addStaParams.sAid=%u\n",__func__,addStaParams.sAid);

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_ADD_STATION_PARAM,(char*)&addStaParams,sizeof(addStaParams));

	return ret;
}


static int wilink_set_channel(void *priv,int mode, int freq)
{
	struct wilink_driver_data *drv = priv;
	TApChannelParams ChannelParams;
	int ret = 0;

    memset(&ChannelParams, 0, sizeof(ChannelParams));
    ChannelParams.cChannel = hostapd_hw_get_channel(drv->hapd,freq);

    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_CHANNEL,(char*)&ChannelParams,sizeof(ChannelParams));
	return ret;

}

static int wilink_sta_remove(void *priv, const u8 *addr)
{
	struct wilink_driver_data *drv = priv;
	TApGeneralParam DelStationParams;
	int ret = 0;

    if (addr == NULL)
       return ret;
    
    memcpy(DelStationParams.cMac,addr,AP_MAC_ADDR);
	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_REMOVE_STATION,(char*)&DelStationParams,sizeof(DelStationParams));
	return ret;

}

static int wilink_set_beacon(const char *iface, void *priv,
		u8 *head, size_t head_len,
		u8 *tail, size_t tail_len)

{
	struct wilink_driver_data *drv = priv;
	TApBeaconParams BeaconParams;
	int ret = 0;

    if ((head == NULL) || (tail == NULL)) 
       return -1;
    
    memcpy(BeaconParams.cHead,head,head_len);
	memcpy(BeaconParams.cTail,tail,tail_len);
	BeaconParams.iHeadLen = head_len;
	BeaconParams.iTailLen = tail_len;
	BeaconParams.sBeaconIntval = drv->beacon_int;
	BeaconParams.iDtimIntval = drv->dtim_int;

	ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_ADD_BEACON_PARAM,(char*)&BeaconParams,sizeof(BeaconParams));
	return ret;

}

static int wilink_set_internal_bridge(void *priv, int value)
{
    struct wilink_driver_data *drv = priv;
    TApGeneralParam bridgeParam;
    int ret = 0;

    bridgeParam.lValue = value;

    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_BSS_BRIDGE,(char*)&bridgeParam,sizeof(bridgeParam));

    return ret;
}

static int wilink_set_encryption (const char *iface, void *priv, const char *alg,
		const u8 *addr, int idx, const u8 *key,
		size_t key_len, int txkey)
{
	struct wilink_driver_data *drv = priv;
	TApAddKeyParams AddKeyParams;
    TApGeneralParam GenParams;
	int ret = 0;

    memset(&AddKeyParams,0,sizeof(AddKeyParams));
    if (addr)
      memcpy(AddKeyParams.cMac,addr,AP_MAC_ADDR);
    else
      memset(AddKeyParams.cMac,0,AP_MAC_ADDR);
   
	if (strcmp(alg, "none") == 0)
	{
		ret  = wilink_send_ti_private_cmd(drv,TWD_DEL_KEY_PARAMS,(char*)&AddKeyParams,sizeof(AddKeyParams));
    }
	else
	{
		if (strcmp(alg, "WEP") == 0)
			AddKeyParams.cAlg = AP_WEP_CIPHER;
		else if (strcmp(alg, "TKIP") == 0)
			AddKeyParams.cAlg = AP_TKIP_CIPHER;
		else if (strcmp(alg, "CCMP") == 0)
			AddKeyParams.cAlg = AP_CCMP_CIPHER;
		else if (strcmp(alg, "IGTK") == 0)
			AddKeyParams.cAlg = AP_IGTK_CIPHER;
		else
			AddKeyParams.cAlg = AP_WEP_CIPHER;

		AddKeyParams.cKeyIndex = idx;
		AddKeyParams.cTxKey = txkey;
		AddKeyParams.ckeyLen = key_len;
		memcpy(AddKeyParams.cKey,key,key_len);

        if ((AddKeyParams.cAlg == AP_WEP_CIPHER)&& (txkey))
        {
          GenParams.lValue = AddKeyParams.cKeyIndex; 
           wilink_send_ti_private_cmd(drv,TWD_SET_DEFAULT_KEY_PARAMS,(char*)&GenParams,sizeof(GenParams));
        }
             
        ret  = wilink_send_ti_private_cmd(drv,TWD_ADD_KEY_PARAMS,(char*)&AddKeyParams,sizeof(AddKeyParams));
        
	}

	return ret;
}

static int wilink_flush(void *priv)
{
	struct wilink_driver_data *drv = priv;
	int ret = 0;

    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_REMOVE_ALL_STATION,NULL,0);
	return ret;
}

static int wilink_commit(void *priv)
{
    struct wilink_driver_data *drv = priv;
    TApGeneralParam GenStruct;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "HAPDTI %s: COMMIT", __func__);

    GenStruct.lValue = drv->hapd->conf->ap_max_inactivity;

    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_COMMIT_CMD,(char*)&GenStruct,sizeof(TApGeneralParam));
    return ret;

}


static int wilink_set_ssid(const char *ifname, void *priv, const u8 *buf,
			int len) {
    struct wilink_driver_data *drv = priv;
    int ret = 0;
    TApSsidParam ssidParam;

    if (buf == NULL)
      return ret;
    
    if (len > AP_MAX_SSID_LEN) {
        wpa_printf(MSG_ERROR, "%s: len is too big", __func__);
        return -1;
    }

    memcpy(ssidParam.cSsid, buf, len);
    ssidParam.iSsidLen = len;
    
    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_SSID,(char *)&ssidParam,sizeof(ssidParam));
    return ret;
}




static struct hostapd_hw_modes *
 wilink_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags)
{
   struct wilink_driver_data *drv = priv;
   TApGeneralParam GenStruct;
   int i,j;
    
   /* Build hw capability table for default regulatory domain (all channels) if country code is not set */
   wilink_send_ti_private_cmd(drv, ROLE_AP_GET_HW, (char*)drv->pRegDomain, sizeof(*drv->pRegDomain));

   if (!drv->hapd->iconf->ieee80211d)
   {
    memcpy(drv->pRegDomain->cCountry, "TI",2);
    regulatory_build_hw_capability(drv->pRegDomainHandle,drv->pRegDomain,drv->hapd->iconf->channel,drv->hapd->iconf->hw_mode);
    GenStruct.lValue = AP_MAX_TX_POWER ;
   }
   else
   {
     if (!(drv->pRegDomain->cCountry[0] || drv->pRegDomain->cCountry[1]))
         regulatory_build_hw_capability(drv->pRegDomainHandle,drv->pRegDomain,drv->hapd->iconf->channel,drv->hapd->iconf->hw_mode);

      for (i=0;i<drv->pRegDomainHandle->NumOfModes;i++)
       for (j=0;j< drv->pRegDomainHandle->modes[i].num_channels;j++)
        if (drv->pRegDomainHandle->modes[i].channels[j].chan == drv->hapd->iconf->channel)
        {
          GenStruct.lValue = drv->pRegDomainHandle->modes[i].channels[j].max_tx_power * 10;
          break;
        }
   }
  
   wilink_send_ti_private_cmd(drv,ROLE_AP_SET_TX_POWER,(char*)&GenStruct,sizeof(TApGeneralParam));
 
   *num_modes =  drv->pRegDomainHandle->NumOfModes;
   *flags = 0;
    
   return drv->pRegDomainHandle->modes;
}

static int
wilink_set_wps_beacon_ie(const char *ifname, void *priv, const u8 *ie,
			  size_t len)
{
    return 0;
}

static int
wilink_set_wps_probe_resp_ie(const char *ifname, void *priv, const u8 *ie,
			      size_t len)
{
	TApWpsIe wpsParam;
	struct wilink_driver_data *drv = priv;
    int ret = 0;

    if (len > AP_MAX_WPS_IE_LEN) {
        wpa_printf(MSG_ERROR, "%s: len is too big", __func__);
        return -1;
    }

    memcpy(wpsParam.cIe, ie, len);
    wpsParam.iIeLen = len;

    ret  = wilink_send_ti_private_cmd(drv,ROLE_AP_SET_PROBE_WPS_IE,(char *)&wpsParam,sizeof(wpsParam));

    ieee802_11_set_beacon(drv->hapd);

    return ret;
}




const struct wpa_driver_ops wpa_driver_wilink_ops = {
		.name = "wilink",
		.init = wilink_init,
		.deinit = wilink_deinit,
		.wireless_event_init = wilink_wireless_event_init,
		.wireless_event_deinit = wilink_wireless_event_deinit,

		.send_eapol = wilink_send_eapol,
		.send_mgmt_frame = wilink_send_mgmt_frame,

		.sta_deauth = wilink_sta_deauth,
		.sta_disassoc = wilink_sta_disassoc,
		
		/* commands */
		.set_privacy = wilink_set_privacy,
		.set_encryption = wilink_set_encryption,
		.flush = wilink_flush,
		.read_sta_data = wilink_read_sta_data,
		.sta_set_flags = wilink_sta_set_flags,
		.sta_remove = wilink_sta_remove,
		.sta_add2 = wilink_sta_add2,
		.set_freq = wilink_set_channel,
		.set_rts = wilink_set_rts,
		.set_rate_sets = wilink_set_rate_sets,
		.set_beacon = wilink_set_beacon,
		.set_internal_bridge = wilink_set_internal_bridge,
		.set_beacon_int = wilink_set_beacon_int,
		.set_dtim_period = wilink_set_dtim_period,
		.set_broadcast_ssid = wilink_set_broadcast_ssid,
		.set_cts_protect = wilink_set_cts_protect,
		.set_preamble = wilink_set_preamble,
		.set_short_slot_time = wilink_set_short_slot_time,
		.set_tx_queue_params = wilink_set_tx_queue_params,
		.set_country = wilink_set_country,
		.commit = wilink_commit,
		.set_ssid = wilink_set_ssid,
		.get_hw_feature_data = wilink_get_hw_feature_data,
		.set_wps_beacon_ie	= wilink_set_wps_beacon_ie,
		.set_wps_probe_resp_ie	= wilink_set_wps_probe_resp_ie,
};
