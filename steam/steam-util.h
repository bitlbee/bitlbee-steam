/*
 * Copyright 2012-2015 James Geboski <jgeboski@gmail.com>
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

#include "steam-glib.h"

#define STEAM_UTIL_ENUM_NULL {0, NULL}

/** The types of log messages. **/
typedef enum _SteamDebugLevel SteamDebugLevel;

/** The structure for holding value/pointer pairs for enumerators. **/
typedef struct _SteamUtilEnum SteamUtilEnum;

/** The structure for holding name/span pairs for time spans. **/
typedef struct _SteamUtilTimeSpan SteamUtilTimeSpan;


/**
 * The types of log messages.
 **/
enum _SteamDebugLevel
{
    STEAM_UTIL_DEBUG_LEVEL_MISC,  /** Miscellaneous. **/
    STEAM_UTIL_DEBUG_LEVEL_INFO,  /** Information. **/
    STEAM_UTIL_DEBUG_LEVEL_WARN,  /** Warning. **/
    STEAM_UTIL_DEBUG_LEVEL_ERROR, /** Error. **/
    STEAM_UTIL_DEBUG_LEVEL_FATAL  /** Fatal. **/
};

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


void steam_util_debug(SteamDebugLevel level, const gchar *format, ...)
    G_GNUC_PRINTF(2, 3);

void steam_util_vdebug(SteamDebugLevel level, const gchar *format, va_list ap);

void steam_util_debug_misc(const gchar *format, ...)
    G_GNUC_PRINTF(1, 2);

void steam_util_debug_info(const gchar *format, ...)
    G_GNUC_PRINTF(1, 2);

void steam_util_debug_warn(const gchar *format, ...)
    G_GNUC_PRINTF(1, 2);

void steam_util_debug_error(const gchar *format, ...)
    G_GNUC_PRINTF(1, 2);

void steam_util_debug_fatal(const gchar *format, ...)
    G_GNUC_PRINTF(1, 2);

gpointer steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def,
                             guint val);

gpointer *steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals);

guint steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                          gconstpointer ptr, GCompareFunc cmpfunc);

GByteArray *steam_util_str_hex2bytes(const gchar *str);

gboolean steam_util_str_iequal(const gchar *s1, const gchar *s2);

gchar *steam_util_time_span_str(GTimeSpan span);

gchar *steam_util_time_since_utc(gint64 timestamp);

gchar *steam_util_ustrchr(const gchar *str, gchar chr);


#endif /* _STEAM_UTIL_H */
