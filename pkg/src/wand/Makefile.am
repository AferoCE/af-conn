AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = wand

wand_SOURCES = at.c ril.c wand.c net.c server.c
wand_LDADD = -laf_attr -laf_ipc -laf_util -lpthread -levent -levent_pthreads -lm -lpcap -lrt -lresolv
wand_CFLAGS = -Wall -ggdb3
