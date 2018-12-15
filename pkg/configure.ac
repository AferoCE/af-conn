AC_INIT([connectivity], [1.0], [bug-automake@gnu.org])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
: ${CFLAGS="-O0"}
AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
 src/wand/Makefile
 src/wifistad/Makefile
 src/atcmd/Makefile
 src/connd/Makefile
])
AM_CONDITIONAL([WAN_RIL_HL7xxx], [test ! x$WAN_RIL = xELS61])
AM_CONDITIONAL([BUILD_TARGET_DEBUG], [test x$BUILD_TARGET = xdebug])
LT_INIT
AC_OUTPUT
