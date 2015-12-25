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

#ifndef _STEAM_UTIL_H_
#define _STEAM_UTIL_H_

/**
 * SECTION:util
 * @section_id: steam-util
 * @short_description: <filename>steam-util.h</filename>
 * @title: General Utilities
 *
 * The general utilities.
 */

#include "steam-glib.h"

/**
 * STEAM_UTIL_ENUM_NULL:
 *
 * The #NULL terminating #SteamUtilEnum.
 */
#define STEAM_UTIL_ENUM_NULL  {0, NULL}

typedef struct _SteamUtilEnum SteamUtilEnum;
typedef struct _SteamUtilTimeSpan SteamUtilTimeSpan;

/**
 * SteamDebugLevel:
 * STEAM_UTIL_DEBUG_LEVEL_MISC: Miscellaneous message.
 * STEAM_UTIL_DEBUG_LEVEL_INFO: Information message.
 * STEAM_UTIL_DEBUG_LEVEL_WARN: Warning message.
 * STEAM_UTIL_DEBUG_LEVEL_ERROR: Error message.
 * STEAM_UTIL_DEBUG_LEVEL_FATAL: Fatal message.
 *
 * The log message types.
 */
typedef enum
{
    STEAM_UTIL_DEBUG_LEVEL_MISC,
    STEAM_UTIL_DEBUG_LEVEL_INFO,
    STEAM_UTIL_DEBUG_LEVEL_WARN,
    STEAM_UTIL_DEBUG_LEVEL_ERROR,
    STEAM_UTIL_DEBUG_LEVEL_FATAL
} SteamDebugLevel;

/**
 * SteamUtilEnum:
 * @val: The value.
 * @ptr: The pointer.
 *
 * Represents a value/pointer pair for an enumerator.
 */
struct _SteamUtilEnum
{
    guint val;
    gpointer ptr;
};

/**
 * SteamUtilTimeSpan:
 * @name: The name.
 * @span: The span.
 *
 * Represents a name/span pair for a time span.
 */
struct _SteamUtilTimeSpan
{
    gchar *name;
    gint64 span;
};

/**
 * steam_util_debug:
 * @level: The #SteamDebugLevel.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message.
 */
void
steam_util_debug(SteamDebugLevel level, const gchar *format, ...)
                 G_GNUC_PRINTF(2, 3);

/**
 * steam_util_vdebug:
 * @level: The #SteamDebugLevel.
 * @format: The format string literal.
 * @ap: The #va_list.
 *
 * Logs a debugging message.
 */
void
steam_util_vdebug(SteamDebugLevel level, const gchar *format, va_list ap);

/**
 * steam_util_debug_misc:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #STEAM_UTIL_DEBUG_LEVEL_MISC.
 *
 */
void
steam_util_debug_misc(const gchar *format, ...)
                      G_GNUC_PRINTF(1, 2);

/**
 * steam_util_debug_info:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #STEAM_UTIL_DEBUG_LEVEL_INFO.
 *
 */
void
steam_util_debug_info(const gchar *format, ...)
                      G_GNUC_PRINTF(1, 2);

/**
 * steam_util_debug_warn:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #STEAM_UTIL_DEBUG_LEVEL_WARN.
 *
 */
void
steam_util_debug_warn(const gchar *format, ...)
                      G_GNUC_PRINTF(1, 2);

/**
 * steam_util_debug_error:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #STEAM_UTIL_DEBUG_LEVEL_ERROR.
 *
 */
void
steam_util_debug_error(const gchar *format, ...)
                       G_GNUC_PRINTF(1, 2);

/**
 * steam_util_debug_fatal:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #STEAM_UTIL_DEBUG_LEVEL_FATAL.
 *
 */
void
steam_util_debug_fatal(const gchar *format, ...)
                       G_GNUC_PRINTF(1, 2);

/**
 * steam_util_enum_ptr:
 * @enums: The array of #SteamUtilEnum.
 * @def: The default return value.
 * @val: The enumerator value.
 *
 * Gets the enumerator pointer from its value.
 *
 * Returns: The enumerator pointer or #NULL on error.
 */
gpointer
steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def, guint val);

/**
 * steam_util_enum_ptrs:
 * @enums: The array of #SteamUtilEnum.
 * @vals: The enumerator values.
 *
 * Gets the enumerator pointers from its value. The returned array
 * should be freed when no longer needed.
 *
 * Returns: The enumerator pointer array.
 */
gpointer *
steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals);

/**
 * steam_util_enum_val:
 * @enums: The array of #SteamUtilEnum.
 * @ptr: The enumerator pointer.
 * @def: The default return value.
 * @cmpfunc: The #GCompareFunc.
 *
 * Gets the enumerator value from its pointer.
 *
 * Returns: The enumerator value or `0` on error.
 */
guint
steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                    gconstpointer ptr, GCompareFunc cmpfunc);

/**
 * steam_util_str_hex2bytes:
 * @str: The hexadecimal string.
 *
 * Converts the hexadecimal string to a #GByteArray. The returned
 * #GByteArray should be freed with #g_byte_array_free() when no
 * longer needed.
 *
 * Returns: The #GByteArray or #NULL on error.
 */
GByteArray *
steam_util_str_hex2bytes(const gchar *str);

/**
 * steam_util_str_iequal:
 * @s1: The first string.
 * @s2: The second string.
 *
 * Compare two strings case insensitively. This is useful for where
 * the return value must be a boolean, such as with a #GEqualFunc.
 *
 * Returns: #TRUE if the strings are equal, otherwise #FALSE.
 */
gboolean
steam_util_str_iequal(const gchar *s1, const gchar *s2);

/**
 * steam_util_time_span_str:
 * @span: The #GTimeSpan.
 *
 * Gets the string representation of the timespan. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * Returns: The string representation.
 */
gchar *
steam_util_time_span_str(GTimeSpan span);

/**
 * steam_util_time_since_utc:
 * @span: The timestamp (UTC).
 *
 * Gets the string representation of the timespan since the given
 * timestamp. The returned string should be freed with #g_free() when
 * no longer needed.
 *
 * Returns: The string representation.
 */
gchar *
steam_util_time_since_utc(gint64 timestamp);

/**
 * steam_util_ustrchr:
 * @str: The string.
 * @chr: The character.
 *
 * Find the first occurrence of the character in a string not contained
 * inside quotes (single or double).
 *
 * Returns: A pointer to the character or #NULL on error.
 */
gchar *
steam_util_ustrchr(const gchar *str, gchar chr);

#endif /* _STEAM_UTIL_H_ */
