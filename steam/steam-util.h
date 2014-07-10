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

/** @file **/

#ifndef _STEAM_UTIL_H
#define _STEAM_UTIL_H

#include <glib.h>

/** The structure for holding value/pointer pairs for enumerators. **/
typedef struct _SteamUtilEnum SteamUtilEnum;

/** The structure for holding name/span pairs for time spans. **/
typedef struct _SteamUtilTimeSpan SteamUtilTimeSpan;


/**
 * The structure for holding value/pointer pairs for enumerators.
 **/
struct _SteamUtilEnum
{
    guint    val; /** The value. **/
    gpointer ptr; /** The pointer. **/
};

/**
 * The structure for holding name/span pairs for time spans.
 **/
struct _SteamUtilTimeSpan
{
    gchar  *name; /** The name. **/
    gint64  span; /** The span. **/
};


gpointer steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def,
                             guint val);

gpointer *steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals);

guint steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                          gconstpointer ptr, GCompareFunc cmpfunc);

gchar *steam_util_markup_unescape_text(const gchar *text);

gchar *steam_util_rsa_encrypt(const gchar *pkmod, const gchar *pkexp,
                              const gchar *str);

gboolean steam_util_str_iequal(const gchar *s1, const gchar *s2);

gchar *steam_util_time_span_str(GTimeSpan span);

gchar *steam_util_time_since_utc(gint64 timestamp);

gchar *steam_util_ustrchr(const gchar *str, gchar chr);


#endif /* _STEAM_UTIL_H */
