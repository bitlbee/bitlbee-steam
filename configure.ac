AC_INIT(
    [bitlbee-steam],
    [0.1.0],
    [https://github.com/jgeboski/bitlbee-steam/issues])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AC_PREFIX_DEFAULT([/usr])
AM_INIT_AUTOMAKE([no-define])

AC_PROG_CC
AM_PROG_CC_C_O

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_WITH(
    [plugindir],
    [AS_HELP_STRING(
        [--with-plugindir],
        [BitlBee plugin directory])],
    [plugindir="$with_plugindir"],
    [plugindir="$libdir/bitlbee"]
)

m4_define_default(
    [PKG_CHECK_MODULES],
    [AC_MSG_CHECKING([$1])
     AC_MSG_RESULT([no])]
    [AC_MSG_ERROR([Package requirements (pkg-config) were not met.])])

PKG_CHECK_MODULES([GLIB],    [glib-2.0])
PKG_CHECK_MODULES([BITLBEE], [bitlbee])

# No "reliable" version set in bitlbee.pc, check manually
CPPFLAGS="$GLIB_CFLAGS $BITLBEE_CFLAGS"
AC_MSG_CHECKING([for bitlbee >= 3.2])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <bitlbee.h>
        #if BITLBEE_VERSION_CODE < BITLBEE_VER(3, 2, 0)
        #error outdated bitlbee version
        #endif]], [])],
    [HAVE_REQ_BITLBEE=yes],
    [HAVE_REQ_BITLBEE=no])

AC_MSG_RESULT([$HAVE_REQ_BITLBEE])

AS_IF(
    [test "x$HAVE_REQ_BITLBEE" == "xno"],
    [AC_MSG_ERROR([Package requirements (bitlbee >= 3.2) were not met.])])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_FILES([Makefile steam/Makefile])
AC_SUBST([plugindir])
AC_OUTPUT
