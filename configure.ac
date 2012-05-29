AC_INIT([bitlbee-steam], [0.1.0],
        [https://github.com/jgeboski/bitlbee-steam/issues])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT([/usr])

AM_INIT_AUTOMAKE()

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_CHECK_MODULES([GLIB],    [glib-2.0])
PKG_CHECK_MODULES([JSON],    [json])
PKG_CHECK_MODULES([BITLBEE], [bitlbee])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_FILES([Makefile steam/Makefile])
AC_OUTPUT
