AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = wifistad
include_HEADERS = wifista_shared_types.h

if BUILD_TARGET_DEBUG
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_DEBUG
else
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_RELEASE
endif

wifistad_SOURCES =	wifistad.c \
					wpa_manager.c \
					os_unix.c \
					wpa_ctrl.c \
					mac_whitelist.c \
					common.c \
					cached_ap_list.c \
					wpa_wifi_setup.c \
					wifistad_attributes.c \
					../connd/hub_config.c \
					../common/netcheck_async.c

wifistad_LDADD = -laf_attr -laf_ipc -lafwp -laf_util -lpthread -levent -levent_pthreads -lm -lpcap -lrt
wifistad_CFLAGS = -Wall -std=gnu99 -I../../include -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX -D_GNU_SOURCE $(CFLAGS_BUILD_TARGET)

.PHONY : build_info.h
$(wifistad_SOURCES) : build_info.h
build_info.h :
	$(srcdir)/make-build-info.sh $(srcdir)
