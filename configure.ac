AC_INIT([bitlbee-steam], [0.1.0],
        [https://github.com/jgeboski/bitlbee-steam/issues])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT([/usr])

AM_INIT_AUTOMAKE()

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_ARG_WITH([plugindir],
            [AS_HELP_STRING([--with-plugindir],
                            [BitlBee plugin directory])],
            [plugindir="$with_plugindir"],
            [plugindir="$libdir/bitlbee"])

PKG_CHECK_MODULES([GLIB],    [glib-2.0])
PKG_CHECK_MODULES([BITLBEE], [bitlbee])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_FILES([Makefile steam/Makefile])
AC_OUTPUT

AC_SUBST([plugindir])
