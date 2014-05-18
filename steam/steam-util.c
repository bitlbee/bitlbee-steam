/*
 * Copyright 2012-2014 James Geboski <jgeboski@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "steam-util.h"

/**
 * Gets the enumerator pointer from its value.
 *
 * @param enums The array of #SteamUtilEnum.
 * @param def   The default return value.
 * @param val   The enumerator value.
 *
 * @return The enumerator pointer, or NULL on error.
 **/
gpointer steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def,
                             guint val)
{
    guint i;

    g_return_val_if_fail(enums != NULL, NULL);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (enums[i].val == val)
            return enums[i].ptr;
    }

    return def;
}

/**
 * Gets the enumerator value from its pointer.
 *
 * @param enums   The array of #SteamUtilEnum.
 * @param ptr     The enumerator pointer.
 * @param def     The default return value.
 * @param cmpfunc The #GCompareFunc.
 *
 * @return The enumerator value, or 0 on error.
 **/
guint steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                          gconstpointer ptr, GCompareFunc cmpfunc)
{
    guint i;

    g_return_val_if_fail(enums   != NULL, 0);
    g_return_val_if_fail(ptr     != NULL, 0);
    g_return_val_if_fail(cmpfunc != NULL, 0);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (cmpfunc(ptr, enums[i].ptr) == 0)
            return enums[i].val;
    }

    return def;
}

/**
 * Find the first occurrence of a character in a string not contained
 * inside quotes (single or double).
 *
 * @param str The string.
 * @param chr The character.
 *
 * @return A pointer to the character, or NULL if it was not found.
 **/
gchar *steam_util_ustrchr(const gchar *str, gchar chr)
{
    gchar  qc;
    gsize  ssz;
    gsize  cs;
    gsize  i;
    gssize j;

    if (G_UNLIKELY(str == NULL))
        return NULL;

    ssz = strlen(str);

    for (qc = i = 0; i < ssz; i++) {
        if ((qc == 0) && (str[i] == chr))
            return (gchar *) str + i;

        if ((str[i] != '"') && (str[i] != '\''))
            continue;

        if ((qc != 0) && (str[i] != qc))
            continue;

        for (cs = 0, j = i - 1; (j >= 0) && (str[j] == '\\'); j--, cs++);

        if ((cs % 2) == 0)
            qc = (qc == 0) ? str[i] : 0;
    }

    return NULL;
}
