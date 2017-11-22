AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = wand

if WAN_RIL_HL7xxx
wand_SOURCES = at_HL7xxx.c ril_HL7xxx.c wand.c net.c server.c
else
wand_SOURCES = at_ELS61.c ril_ELS61.c wand.c net.c server.c
endif

wand_LDADD = -laf_attr -laf_ipc -laf_util -lpthread -levent -levent_pthreads -lm -lpcap -lrt -lresolv
wand_CFLAGS = -Wall -ggdb3

.PHONY : build_info.h
$(wand_SOURCES) : build_info.h
build_info.h :
	$(srcdir)/make-build-info.sh $(srcdir)
