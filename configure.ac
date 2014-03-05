# Copyright 2012-2014 James Geboski <jgeboski@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT(
    [bitlbee-steam],
    [1.0.0],
    [https://github.com/jgeboski/bitlbee-steam/issues],
    [bitlbee-steam],
    [https://github.com/jgeboski/bitlbee-steam],
    []
)

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([no-define])

AC_PROG_CC
AM_PROG_CC_C_O

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AC_PROG_CC_C99],  [AC_PROG_CC_C99])

AC_ARG_ENABLE(
    [debug],
    [AS_HELP_STRING(
        [--enable-debug],
        [Enable debugging features]
    )], [
        AC_DEFINE(DEBUG_STEAM, 1)
        CFLAGS="$CFLAGS -Wall -g -O0"
    ]
)

AC_ARG_WITH(
    [plugindir],
    [AS_HELP_STRING(
        [--with-plugindir],
        [BitlBee plugin directory]
    )],
    [plugindir="$with_plugindir"],
    [plugindir="$libdir/bitlbee"]
)

m4_define_default(
    [PKG_CHECK_MODULES], [
        AC_MSG_CHECKING([$1])
        AC_MSG_RESULT([no])
    ],
    [AC_MSG_ERROR([Package requirements (pkg-config) were not met.])]
)

AC_CHECK_LIB(
    [gmp],
    [__gmpz_init],
    [HAVE_GMP_LIB=yes],
    [HAVE_GMP_LIB=no]
)

AC_CHECK_HEADER(
    [gmp.h],
    [HAVE_GMP_HEADER=yes],
    [HAVE_GMP_HEADER=no]
)

AS_IF(
    [test "x$HAVE_GMP_LIB" == "xno" -o "x$HAVE_GMP_HEADER" == "xno"],
    [AC_MSG_ERROR([Package requirements (GMP) were not met.])],
    [GMP_LIBS=-lgmp]
)

PKG_CHECK_MODULES([GLIB],    [glib-2.0])
PKG_CHECK_MODULES([BITLBEE], [bitlbee])

# Check for "real" bitlbee headers
CPPFLAGS="$GLIB_CFLAGS $BITLBEE_CFLAGS"
AC_MSG_CHECKING([for bitlbee headers])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([[
        #define HAVE_CONFIG_H 1
        #include <bitlbee.h>
        #include <http_client.h>
    ]], [])],
    [HAVE_BITLBEE_HEADERS=yes],
    [HAVE_BITLBEE_HEADERS=no]
)

AC_MSG_RESULT([$HAVE_BITLBEE_HEADERS])

AS_IF(
    [test "x$HAVE_BITLBEE_HEADERS" == "xno"],
    [AC_MSG_ERROR([Failed to find required bitlbee headers.])]
)

# No "reliable" version set in bitlbee.pc, check manually
CPPFLAGS="$GLIB_CFLAGS $BITLBEE_CFLAGS"
AC_MSG_CHECKING([for bitlbee >= 3.2.1])
AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
        #include <bitlbee.h>
        #if BITLBEE_VERSION_CODE < BITLBEE_VER(3, 2, 0)
        #error outdated bitlbee version
        #endif
    ]], [[
        #if BITLBEE_VERSION_CODE == BITLBEE_VER(3, 2, 0)
        #include <stdlib.h>
        #include <string.h>

        size_t size = strlen(BITLBEE_VERSION);
        if (size != 5) return EXIT_FAILURE;

        char *c = strrchr(BITLBEE_VERSION, '.');
        if (c == NULL) return EXIT_FAILURE;

        int m = atoi(c + 1);
        if (m < 1) return EXIT_FAILURE;

        return EXIT_SUCCESS;
        #endif
    ]])],
    [HAVE_BITLBEE_REQ=yes],
    [HAVE_BITLBEE_REQ=no]
)

AC_MSG_RESULT([$HAVE_BITLBEE_REQ])

AS_IF(
    [test "x$HAVE_BITLBEE_REQ" == "xno"],
    [AC_MSG_ERROR([Package requirements (bitlbee >= 3.2.1) were not met.])]
)

AC_CONFIG_FILES([Makefile steam/Makefile])
AC_SUBST([GMP_LIBS])
AC_SUBST([plugindir])
AC_OUTPUT
