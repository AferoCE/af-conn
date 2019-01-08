AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = connmgr

if BUILD_TARGET_DEBUG
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_DEBUG
else
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_RELEASE
endif

if BUILD_TYPE_DEV
CFLAGS_BUILD_TYPE = -DBUILD_TYPE_DEV
else
CFLAGS_BUILD_TYPE = -DBUILD_TYPE_PROD
endif

connmgr_SOURCES = connmgr.c 	  \
				  traffic_mon.c   \
				  connmgr_stats.c \
				  connmgr_select_engine.c \
				  connmgr_extract_dns.c   \
				  hub_wifi_info.c \
				  hub_netconn_status.c \
				  connmgr_util.c \
				  connmgr_attributes.c \
				  wildcard_match.c \
				  ../common/netcheck_async.c

connmgr_LDADD = -laf_attr -laf_ipc -laf_util -lpthread -levent -levent_pthreads -lm -lpcap -lrt
connmgr_CFLAGS = -Wall $(CFLAGS_BUILD_TARGET) $(CFLAGS_BUILD_TYPE)

.PHONY : build_info.h
$(connmgr_SOURCES): build_info.h
build_info.h :
	$(srcdir)/make-build-info.sh $(srcdir)
