# Copyright 2012-2016 James Geboski <jgeboski@gmail.com>
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
    [1.4.2],
    [https://github.com/jgeboski/bitlbee-steam/issues],
    [bitlbee-steam],
    [https://github.com/jgeboski/bitlbee-steam],
    []
)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([no-define])

AC_PROG_CC
AM_PROG_CC_C_O

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AC_PROG_CC_C99],  [AC_PROG_CC_C99])

# Define PKG_CHECK_VAR() for pkg-config < 0.28
m4_define_default(
    [PKG_CHECK_VAR],
    [AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])
     AS_IF([test -z "$$1"], [$1=`$PKG_CONFIG --variable="$3" "$2"`])
     AS_IF([test -n "$$1"], [$4], [$5])]
)

AC_ARG_ENABLE(
    [warnings],
    [AS_HELP_STRING(
        [--enable-warnings],
        [Enable additional compile-time (GCC) warnings]
    )],
    [WARNINGS="$enableval"],
    [WARNINGS="no"]
)

AS_IF(
    [test "x$WARNINGS" = "xyes"],
    [CFLAGS="$CFLAGS -Wall -Wextra \
     -Waggregate-return \
     -Wdeclaration-after-statement \
     -Wfloat-equal \
     -Wformat \
     -Winit-self \
     -Wmissing-declarations \
     -Wmissing-prototypes \
     -Wno-unused-parameter \
     -Wpointer-arith"]
)

AC_ARG_WITH(
    [plugindir],
    [AS_HELP_STRING(
        [--with-plugindir],
        [BitlBee plugin directory]
    )],
    [plugindir="$withval"]
)

AM_PATH_LIBGCRYPT([1.5.0])
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.28.0])
PKG_CHECK_MODULES([BITLBEE], [bitlbee  >= 3.4])

AS_IF(
    [test -z "$plugindir"],
    [PKG_CHECK_VAR(
        [BITLBEE_PLUGINDIR],
        [bitlbee],
        [plugindir],
        [plugindir="$BITLBEE_PLUGINDIR"],
        [plugindir="$libdir/bitlbee"]
    )]
)

AC_CONFIG_FILES([Makefile steam/Makefile])
AC_SUBST([plugindir])
AC_OUTPUT
