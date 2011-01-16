ifneq ($(BOARD_SOFTAP_DEVICE),)

LOCAL_PATH := $(call my-dir)

ifndef AP_CFLAGS
AP_CFLAGS = -MMD -O2 -Wall -g
endif

# define HOSTAPD_DUMP_STATE to include SIGUSR1 handler for dumping state to
# a file (undefine it, if you want to save in binary size)
AP_CFLAGS += -DHOSTAPD_DUMP_STATE

C_INCLUDES = \
	$(LOCAL_PATH)/src \
	$(LOCAL_PATH)/src/crypto \
	$(LOCAL_PATH)/src/utils \
	$(LOCAL_PATH)/src/common \
	external/openssl/include

# Uncomment following line and set the path to your kernel tree include
# directory if your C library does not include all header files.
# AP_CFLAGS += -DUSE_KERNEL_HEADERS +I/usr/src/linux/include

include $(LOCAL_PATH)/hostapd/.config

ifndef AP_CONFIG_OS
ifdef AP_CONFIG_NATIVE_WINDOWS
AP_CONFIG_OS=win32
else
AP_CONFIG_OS=unix
endif
endif

ifeq ($(AP_CONFIG_OS), internal)
AP_CFLAGS += -DOS_NO_C_LIB_DEFINES
endif

ifdef AP_CONFIG_NATIVE_WINDOWS
AP_CFLAGS += -DCONFIG_NATIVE_WINDOWS
LIBS += -lws2_32
endif

OBJS =	hostapd/hostapd.c              \
	hostapd/ieee802_1x.c           \
	hostapd/eapol_sm.c             \
	hostapd/ieee802_11.c           \
	hostapd/config.c               \
	hostapd/ieee802_11_auth.c      \
	hostapd/accounting.c           \
	hostapd/sta_info.c             \
	hostapd/wpa.c                  \
	hostapd/ctrl_iface.c           \
	hostapd/drivers.c              \
	hostapd/preauth.c              \
	hostapd/pmksa_cache.c          \
	hostapd/beacon.c               \
	hostapd/hw_features.c          \
	hostapd/wme.c                  \
	hostapd/ap_list.c              \
	hostapd/mlme.c                 \
	hostapd/vlan_init.c            \
	hostapd/wpa_auth_ie.c          \
	src/utils/eloop.c              \
	src/utils/common.c             \
	src/utils/wpa_debug.c          \
	src/utils/wpabuf.c             \
	src/utils/os_$(AP_CONFIG_OS).c \
	src/utils/ip_addr.c            \
	src/common/ieee802_11_common.c \
	src/common/wpa_common.c        \
	src/radius/radius.c            \
	src/radius/radius_client.c     \
	src/crypto/md5.c               \
	src/crypto/rc4.c               \
	src/crypto/md4.c               \
	src/crypto/sha1.c              \
	src/crypto/des.c               \
	src/crypto/aes_wrap.c          \
	src/crypto/aes.c


HOBJS=src/hlr_auc_gw/hlr_auc_gw.c src/utils/common.c src/utils/wpa_debug.c src/utils/os_$(AP_CONFIG_OS).c src/hlr_auc_gw/milenage.c src/crypto/aes_wrap.c src/crypto/aes.c

AP_CFLAGS += -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX

ifdef AP_CONFIG_IAPP
AP_CFLAGS += -DCONFIG_IAPP
OBJS += hostapd/iapp.c
endif

ifdef AP_CONFIG_RSN_PREAUTH
AP_CFLAGS += -DCONFIG_RSN_PREAUTH
AP_CONFIG_L2_PACKET=y
endif

ifdef AP_CONFIG_PEERKEY
AP_CFLAGS += -DCONFIG_PEERKEY
OBJS += hostapd/peerkey.c
endif

ifdef AP_CONFIG_IEEE80211W
AP_CFLAGS += -DCONFIG_IEEE80211W
AP_NEED_SHA256=y
endif

ifdef AP_CONFIG_IEEE80211R
AP_CFLAGS += -DCONFIG_IEEE80211R
OBJS += hostapd/wpa_ft.c
AP_NEED_SHA256=y
endif

ifdef AP_CONFIG_IEEE80211N
AP_CFLAGS += -DCONFIG_IEEE80211N
endif

ifdef AP_CONFIG_DRIVER_HOSTAP
AP_CFLAGS += -DCONFIG_DRIVER_HOSTAP
OBJS += hostapd/driver_hostap.c
endif

ifdef AP_CONFIG_DRIVER_WILINK
TI_HOSTAPD_LIB = y
AP_CFLAGS += -DCONFIG_DRIVER_WILINK
C_INCLUDES += \
	hardware/ti/wlan/$(BOARD_SOFTAP_DEVICE)_softAP/stad/Export_Inc \
	hardware/ti/wlan/$(BOARD_SOFTAP_DEVICE)_softAP/utils \
	hardware/ti/wlan/$(BOARD_SOFTAP_DEVICE)_softAP/platforms/os/linux/inc

AP_CONFIG_L2_PACKET=linux
OBJS += hostapd/regulatory.c
OBJS += hostapd/driver_wilink.c 
endif

ifdef AP_CONFIG_DRIVER_WIRED
AP_CFLAGS += -DCONFIG_DRIVER_WIRED
OBJS += hostapd/driver_wired.c
endif

ifdef AP_CONFIG_DRIVER_MADWIFI
AP_CFLAGS += -DCONFIG_DRIVER_MADWIFI
OBJS += hostapd/driver_madwifi.c
AP_CONFIG_L2_PACKET=y
endif

ifdef AP_CONFIG_DRIVER_ATHEROS
AP_CFLAGS += -DCONFIG_DRIVER_ATHEROS
OBJS += hostapd/driver_atheros.c
AP_CONFIG_L2_PACKET=y
endif

ifdef AP_CONFIG_DRIVER_PRISM54
AP_CFLAGS += -DCONFIG_DRIVER_PRISM54
OBJS += hostapd/driver_prism54.c
endif

ifdef AP_CONFIG_DRIVER_NL80211
AP_CFLAGS += -DCONFIG_DRIVER_NL80211
OBJS += hostapd/driver_nl80211.c hostapd/radiotap.c
LIBS += -lnl
ifdef AP_CONFIG_LIBNL20
LIBS += -lnl-genl
AP_CFLAGS += -DCONFIG_LIBNL20
endif
endif

ifdef AP_CONFIG_DRIVER_BSD
AP_CFLAGS += -DCONFIG_DRIVER_BSD
OBJS += hostapd/driver_bsd.c
AP_CONFIG_L2_PACKET=y
AP_CONFIG_DNET_PCAP=y
AP_CONFIG_L2_FREEBSD=y
endif

ifdef AP_CONFIG_DRIVER_TEST
AP_CFLAGS += -DCONFIG_DRIVER_TEST
OBJS += hostapd/driver_test.c
endif

ifdef AP_CONFIG_DRIVER_NONE
AP_CFLAGS += -DCONFIG_DRIVER_NONE
OBJS += hostapd/driver_none.c
endif

ifdef AP_CONFIG_L2_PACKET
ifdef AP_CONFIG_DNET_PCAP
ifdef AP_CONFIG_L2_FREEBSD
LIBS += -lpcap
OBJS += src/l2_packet/l2_packet_freebsd.c
else
LIBS += -ldnet -lpcap
OBJS += src/l2_packet/l2_packet_pcap.c
endif
else
OBJS += src/l2_packet/l2_packet_linux.c
endif
else
OBJS += src/l2_packet/l2_packet_none.c
endif


ifdef AP_CONFIG_EAP_MD5
AP_CFLAGS += -DEAP_MD5
OBJS += src/eap_server/eap_md5.c
AP_CHAP=y
endif

ifdef AP_CONFIG_EAP_TLS
AP_CFLAGS += -DEAP_TLS
OBJS += src/eap_server/eap_tls.c
AP_TLS_FUNCS=y
endif

ifdef AP_CONFIG_EAP_PEAP
AP_CFLAGS += -DEAP_PEAP
OBJS += src/eap_server/eap_peap.c
OBJS += src/eap_common/eap_peap_common.c
AP_TLS_FUNCS=y
AP_CONFIG_EAP_MSCHAPV2=y
endif

ifdef AP_CONFIG_EAP_TTLS
AP_CFLAGS += -DEAP_TTLS
OBJS += src/eap_server/eap_ttls.c
AP_TLS_FUNCS=y
AP_CHAP=y
endif

ifdef AP_CONFIG_EAP_MSCHAPV2
AP_CFLAGS += -DEAP_MSCHAPv2
OBJS += src/eap_server/eap_mschapv2.c
AP_MS_FUNCS=y
endif

ifdef AP_CONFIG_EAP_GTC
AP_CFLAGS += -DEAP_GTC
OBJS += src/eap_server/eap_gtc.c
endif

ifdef AP_CONFIG_EAP_SIM
AP_CFLAGS += -DEAP_SIM
OBJS += src/eap_server/eap_sim.c
AP_CONFIG_EAP_SIM_COMMON=y
endif

ifdef AP_CONFIG_EAP_AKA
AP_CFLAGS += -DEAP_AKA
OBJS += src/eap_server/eap_aka.c
AP_CONFIG_EAP_SIM_COMMON=y
endif

ifdef AP_CONFIG_EAP_AKA_PRIME
AP_CFLAGS += -DEAP_AKA_PRIME
endif

ifdef AP_CONFIG_EAP_SIM_COMMON
OBJS += src/eap_common/eap_sim_common.c
# Example EAP-SIM/AKA interface for GSM/UMTS authentication. This can be
# replaced with another file implementating the interface specified in
# eap_sim_db.h.
OBJS += src/eap_server/eap_sim_db.c
AP_NEED_FIPS186_2_PRF=y
endif

ifdef AP_CONFIG_EAP_PAX
AP_CFLAGS += -DEAP_PAX
OBJS += src/eap_server/eap_pax.c src/eap_common/eap_pax_common.c
endif

ifdef AP_CONFIG_EAP_PSK
AP_CFLAGS += -DEAP_PSK
OBJS += src/eap_server/eap_psk.c src/eap_common/eap_psk_common.c
endif

ifdef AP_CONFIG_EAP_SAKE
AP_CFLAGS += -DEAP_SAKE
OBJS += src/eap_server/eap_sake.c src/eap_common/eap_sake_common.c
endif

ifdef AP_CONFIG_EAP_GPSK
AP_CFLAGS += -DEAP_GPSK
OBJS += src/eap_server/eap_gpsk.c src/eap_common/eap_gpsk_common.c
ifdef AP_CONFIG_EAP_GPSK_SHA256
AP_CFLAGS += -DEAP_GPSK_SHA256
endif
AP_NEED_SHA256=y
endif

ifdef AP_CONFIG_EAP_VENDOR_TEST
AP_CFLAGS += -DEAP_VENDOR_TEST
OBJS += src/eap_server/eap_vendor_test.c
endif

ifdef AP_CONFIG_EAP_FAST
AP_CFLAGS += -DEAP_FAST
OBJS += src/eap_server/eap_fast.c
OBJS += src/eap_common/eap_fast_common.c
AP_TLS_FUNCS=y
AP_NEED_T_PRF=y
endif

ifdef AP_CONFIG_WPS
AP_CFLAGS += -DCONFIG_WPS -DEAP_WSC
OBJS += src/utils/uuid.c
OBJS += hostapd/wps_hostapd.c
OBJS += src/eap_server/eap_wsc.c src/eap_common/eap_wsc_common.c
OBJS += src/wps/wps.c
OBJS += src/wps/wps_common.c
OBJS += src/wps/wps_attr_parse.c
OBJS += src/wps/wps_attr_build.c
OBJS += src/wps/wps_attr_process.c
OBJS += src/wps/wps_dev_attr.c
OBJS += src/wps/wps_enrollee.c
OBJS += src/wps/wps_registrar.c
AP_NEED_DH_GROUPS=y
AP_NEED_SHA256=y
AP_NEED_CRYPTO=y
AP_NEED_BASE64=y

ifdef AP_CONFIG_WPS_UPNP
AP_CFLAGS += -DCONFIG_WPS_UPNP
OBJS += src/wps/wps_upnp.c
OBJS += src/wps/wps_upnp_ssdp.c
OBJS += src/wps/wps_upnp_web.c
OBJS += src/wps/wps_upnp_event.c
OBJS += src/wps/httpread.c
endif

endif

ifdef AP_CONFIG_EAP_IKEV2
AP_CFLAGS += -DEAP_IKEV2
OBJS += src/eap_server/eap_ikev2.c src/eap_server/ikev2.c
OBJS += src/eap_common/eap_ikev2_common.c src/eap_common/ikev2_common.c
AP_NEED_DH_GROUPS=y
endif

ifdef AP_CONFIG_EAP_TNC
AP_CFLAGS += -DEAP_TNC
OBJS += src/eap_server/eap_tnc.c
OBJS += src/eap_server/tncs.c
AP_NEED_BASE64=y
ifndef AP_CONFIG_DRIVER_BSD
LIBS += -ldl
endif
endif

# Basic EAP functionality is needed for EAPOL
OBJS += src/eap_server/eap.c
OBJS += src/eap_common/eap_common.c
OBJS += src/eap_server/eap_methods.c
OBJS += src/eap_server/eap_identity.c

ifdef AP_CONFIG_EAP
AP_CFLAGS += -DEAP_SERVER
endif

ifndef AP_CONFIG_TLS
AP_CONFIG_TLS=openssl
endif

ifeq ($(AP_CONFIG_TLS), internal)
ifndef AP_CONFIG_CRYPTO
AP_CONFIG_CRYPTO=internal
endif
endif
ifeq ($(AP_CONFIG_CRYPTO), libtomcrypt)
AP_CFLAGS += -DCONFIG_INTERNAL_X509
endif
ifeq ($(AP_CONFIG_CRYPTO), internal)
AP_CFLAGS += -DCONFIG_INTERNAL_X509
endif


ifdef AP_TLS_FUNCS
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, and EAP_TTLS)
AP_CFLAGS += -DEAP_TLS_FUNCS
OBJS += src/eap_server/eap_tls_common.c
AP_NEED_TLS_PRF=y
ifeq ($(AP_CONFIG_TLS), openssl)
OBJS += src/crypto/tls_openssl.c
LIBS += -lssl -lcrypto
LIBS_p += -lcrypto
LIBS_h += -lcrypto
endif
ifeq ($(AP_CONFIG_TLS), gnutls)
OBJS += src/crypto/tls_gnutls.c
LIBS += -lgnutls -lgcrypt -lgpg-error
LIBS_p += -lgcrypt
LIBS_h += -lgcrypt
endif
ifdef AP_CONFIG_GNUTLS_EXTRA
AP_CFLAGS += -DCONFIG_GNUTLS_EXTRA
LIBS += -lgnutls-extra
endif
ifeq ($(AP_CONFIG_TLS), internal)
OBJS += src/crypto/tls_internal.c
OBJS += src/tls/tlsv1_common.c src/tls/tlsv1_record.c
OBJS += src/tls/tlsv1_cred.c src/tls/tlsv1_server.c
OBJS += src/tls/tlsv1_server_write.c src/tls/tlsv1_server_read.c
OBJS += src/tls/asn1.c src/tls/x509v3.c
OBJS_p += src/tls/asn1.c
OBJS_p += src/crypto/rc4.c src/crypto/aes_wrap.c src/crypto/aes.c
AP_NEED_BASE64=y
AP_CFLAGS += -DCONFIG_TLS_INTERNAL
AP_CFLAGS += -DCONFIG_TLS_INTERNAL_SERVER
ifeq ($(AP_CONFIG_CRYPTO), internal)
ifdef AP_CONFIG_INTERNAL_LIBTOMMATH
AP_CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
else
LIBS += -ltommath
LIBS_p += -ltommath
endif
endif
ifeq ($(AP_CONFIG_CRYPTO), libtomcrypt)
LIBS += -ltomcrypt -ltfm
LIBS_p += -ltomcrypt -ltfm
endif
endif
AP_NEED_CRYPTO=y
else
OBJS += src/crypto/tls_none.c
endif

ifdef AP_CONFIG_PKCS12
AP_CFLAGS += -DPKCS12_FUNCS
endif

ifdef AP_MS_FUNCS
OBJS += src/crypto/ms_funcs.c
AP_NEED_CRYPTO=y
endif

ifdef AP_CHAP
OBJS += src/eap_common/chap.c
endif

ifdef AP_NEED_CRYPTO
ifndef AP_TLS_FUNCS
ifeq ($(AP_CONFIG_TLS), openssl)
LIBS += -lcrypto
LIBS_p += -lcrypto
LIBS_h += -lcrypto
endif
ifeq ($(AP_CONFIG_TLS), gnutls)
LIBS += -lgcrypt
LIBS_p += -lgcrypt
LIBS_h += -lgcrypt
endif
ifeq ($(AP_CONFIG_TLS), internal)
ifeq ($(AP_CONFIG_CRYPTO), libtomcrypt)
LIBS += -ltomcrypt -ltfm
LIBS_p += -ltomcrypt -ltfm
endif
endif
endif
ifeq ($(AP_CONFIG_TLS), openssl)
OBJS += src/crypto/crypto_openssl.c
OBJS_p += src/crypto/crypto_openssl.c
HOBJS += src/crypto/crypto_openssl.c
AP_CONFIG_INTERNAL_SHA256=y
endif
ifeq ($(AP_CONFIG_TLS), gnutls)
OBJS += src/crypto/crypto_gnutls.c
OBJS_p += src/crypto/crypto_gnutls.c
HOBJS += src/crypto/crypto_gnutls.c
AP_CONFIG_INTERNAL_SHA256=y
endif
ifeq ($(AP_CONFIG_TLS), internal)
ifeq ($(AP_CONFIG_CRYPTO), libtomcrypt)
OBJS += src/crypto/crypto_libtomcrypt.c
OBJS_p += src/crypto/crypto_libtomcrypt.c
AP_CONFIG_INTERNAL_SHA256=y
endif
ifeq ($(AP_CONFIG_CRYPTO), internal)
OBJS += src/crypto/crypto_internal.c src/tls/rsa.c src/tls/bignum.c
OBJS_p += src/crypto/crypto_internal.c src/tls/rsa.c src/tls/bignum.c
AP_CFLAGS += -DCONFIG_CRYPTO_INTERNAL
AP_CONFIG_INTERNAL_AES=y
AP_CONFIG_INTERNAL_DES=y
AP_CONFIG_INTERNAL_SHA1=y
AP_CONFIG_INTERNAL_MD4=y
AP_CONFIG_INTERNAL_MD5=y
AP_CONFIG_INTERNAL_SHA256=y
endif
endif
else
AP_CONFIG_INTERNAL_AES=y
AP_CONFIG_INTERNAL_SHA1=y
AP_CONFIG_INTERNAL_MD5=y
AP_CONFIG_INTERNAL_SHA256=y
endif

ifdef AP_CONFIG_INTERNAL_AES
AP_CFLAGS += -DINTERNAL_AES
endif
ifdef AP_CONFIG_INTERNAL_SHA1
AP_CFLAGS += -DINTERNAL_SHA1
endif
ifdef AP_CONFIG_INTERNAL_SHA256
AP_CFLAGS += -DINTERNAL_SHA256
endif
ifdef AP_CONFIG_INTERNAL_MD5
AP_CFLAGS += -DINTERNAL_MD5
endif
ifdef AP_CONFIG_INTERNAL_MD4
AP_CFLAGS += -DINTERNAL_MD4
endif
ifdef AP_CONFIG_INTERNAL_DES
AP_CFLAGS += -DINTERNAL_DES
endif

ifdef AP_NEED_SHA256
OBJS += src/crypto/sha256.c
endif

ifdef AP_NEED_DH_GROUPS
OBJS += src/crypto/dh_groups.c
endif

ifndef AP_NEED_FIPS186_2_PRF
AP_CFLAGS += -DCONFIG_NO_FIPS186_2_PRF
endif

ifndef AP_NEED_T_PRF
AP_CFLAGS += -DCONFIG_NO_T_PRF
endif

ifndef AP_NEED_TLS_PRF
AP_CFLAGS += -DCONFIG_NO_TLS_PRF
endif

ifdef AP_CONFIG_RADIUS_SERVER
AP_CFLAGS += -DRADIUS_SERVER
OBJS += src/radius/radius_server.c
endif

ifdef AP_CONFIG_IPV6
AP_CFLAGS += -DCONFIG_IPV6
endif

ifdef AP_CONFIG_DRIVER_RADIUS_ACL
AP_CFLAGS += -DCONFIG_DRIVER_RADIUS_ACL
endif

ifdef AP_CONFIG_FULL_DYNAMIC_VLAN
# define AP_CONFIG_FULL_DYNAMIC_VLAN to have hostapd manipulate bridges
# and vlan interfaces for the vlan feature.
AP_CFLAGS += -DCONFIG_FULL_DYNAMIC_VLAN
endif

ifdef AP_NEED_BASE64
OBJS += src/utils/base64.c
endif

ifdef AP_CONFIG_NO_STDOUT_DEBUG
AP_CFLAGS += -DCONFIG_NO_STDOUT_DEBUG
endif

ifdef AP_CONFIG_NO_AES_EXTRAS
AP_CFLAGS += -DCONFIG_NO_AES_UNWRAP
AP_CFLAGS += -DCONFIG_NO_AES_CTR -DCONFIG_NO_AES_OMAC1
AP_CFLAGS += -DCONFIG_NO_AES_EAX -DCONFIG_NO_AES_CBC
AP_CFLAGS += -DCONFIG_NO_AES_DECRYPT
AP_CFLAGS += -DCONFIG_NO_AES_ENCRYPT_BLOCK
endif

ifeq ($(TI_HOSTAPD_LIB), y)
AP_CFLAGS += -DTI_HOSTAPD_CLI_LIB
endif

OBJS_c = \
	hostapd/hostapd_cli.c \
	src/common/wpa_ctrl.c \
	src/utils/os_$(AP_CONFIG_OS).c

########################

include $(CLEAR_VARS)
LOCAL_MODULE := hostap
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libc libcutils libcrypto libssl
#LOCAL_FORCE_STATIC_EXCUTABLE := true
#LOCAL_STATIC_LIBRARIES := libc libcutils
LOCAL_CFLAGS := $(AP_CFLAGS)
LOCAL_SRC_FILES := $(OBJS)
LOCAL_C_INCLUDES := $(C_INCLUDES)
include $(BUILD_EXECUTABLE)

########################

include $(CLEAR_VARS)
LOCAL_MODULE := libhostapdcli
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_CFLAGS := $(AP_CFLAGS)
LOCAL_SRC_FILES := $(OBJS_c)
LOCAL_C_INCLUDES := $(C_INCLUDES)
include $(BUILD_STATIC_LIBRARY)

########################

endif # ! BOARD_SOFTAP_DEVICE
