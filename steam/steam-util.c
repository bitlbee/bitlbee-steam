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

#include <stdarg.h>
#include <string.h>

#include "steam-util.h"

void
steam_util_debug(SteamDebugLevel level, const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(level, format, ap);
    va_end(ap);
}

void
steam_util_vdebug(SteamDebugLevel level, const gchar *format, va_list ap)
{
    const gchar *lstr;
    gchar *str;

    static gboolean debug = FALSE;
    static gboolean setup = FALSE;

    g_return_if_fail(format != NULL);

    if (G_UNLIKELY(!setup)) {
        debug = (g_getenv("BITLBEE_DEBUG") != NULL) ||
                (g_getenv("BITLBEE_DEBUG_STEAM") != NULL);
        setup = TRUE;
    }

    if (!debug) {
        return;
    }

    switch (level) {
    case STEAM_UTIL_DEBUG_LEVEL_MISC:
        lstr = "MISC";
        break;
    case STEAM_UTIL_DEBUG_LEVEL_INFO:
        lstr = "INFO";
        break;
    case STEAM_UTIL_DEBUG_LEVEL_WARN:
        lstr = "WARN";
        break;
    case STEAM_UTIL_DEBUG_LEVEL_ERROR:
        lstr = "ERROR";
        break;
    case STEAM_UTIL_DEBUG_LEVEL_FATAL:
        lstr = "FATAL";
        break;

    default:
        g_return_if_reached();
        return;
    }

    str = g_strdup_vprintf(format, ap);
    g_print("[%s] %s: %s\n", lstr, "steam", str);
    g_free(str);
}

void
steam_util_debug_misc(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(STEAM_UTIL_DEBUG_LEVEL_MISC, format, ap);
    va_end(ap);
}

void
steam_util_debug_info(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(STEAM_UTIL_DEBUG_LEVEL_INFO, format, ap);
    va_end(ap);
}

void
steam_util_debug_warn(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(STEAM_UTIL_DEBUG_LEVEL_WARN, format, ap);
    va_end(ap);
}

void
steam_util_debug_error(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(STEAM_UTIL_DEBUG_LEVEL_ERROR, format, ap);
    va_end(ap);
}

void
steam_util_debug_fatal(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    steam_util_vdebug(STEAM_UTIL_DEBUG_LEVEL_FATAL, format, ap);
    va_end(ap);
}

gpointer
steam_util_enum_ptr(const SteamUtilEnum *enums, gpointer def, guint val)
{
    guint i;

    g_return_val_if_fail(enums != NULL, NULL);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (enums[i].val == val) {
            return enums[i].ptr;
        }
    }

    return def;
}

gpointer *
steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals)
{
    gpointer *ptrs;
    gsize size = 0;
    guint i;
    guint j;

    g_return_val_if_fail(enums != NULL, g_new0(gpointer, 0));

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val) {
            size++;
        }
    }

    ptrs = g_new0(gpointer, ++size);

    for (i = 0, j = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val) {
            ptrs[j++] = enums[i].ptr;
        }
    }

    return ptrs;
}

guint
steam_util_enum_val(const SteamUtilEnum *enums, guint def,
                    gconstpointer ptr, GCompareFunc cmpfunc)
{
    guint i;

    g_return_val_if_fail(enums != NULL, 0);
    g_return_val_if_fail(ptr != NULL, 0);
    g_return_val_if_fail(cmpfunc != NULL, 0);

    for (i = 0; enums[i].ptr != NULL; i++) {
        if (cmpfunc(ptr, enums[i].ptr) == 0) {
            return enums[i].val;
        }
    }

    return def;
}

GByteArray *
steam_util_str_hex2bytes(const gchar *str)
{
    gboolean hax;
    GByteArray *ret;
    gchar val;
    gsize size;
    guint d;
    guint i;

    g_return_val_if_fail(str != NULL, NULL);

    size = strlen(str);
    hax = (size % 2) != 0;

    ret = g_byte_array_new();
    g_byte_array_set_size(ret, (size + 1) / 2);
    memset(ret->data, 0, ret->len);

    for (d = i = 0; i < size; i++, hax = !hax) {
        val = g_ascii_xdigit_value(str[i]);

        if (val < 0) {
            g_byte_array_free(ret, TRUE);
            return NULL;
        }

        if (hax) {
            ret->data[d++] |= val & 0x0F;
        } else {
            ret->data[d] |= (val << 4) & 0xF0;
        }
    }

    return ret;
}

gboolean
steam_util_str_iequal(const gchar *s1, const gchar *s2)
{
    return g_ascii_strcasecmp(s1, s2) == 0;
}

gchar *
steam_util_time_span_str(GTimeSpan span)
{
    gchar *str;
    guint i;

    static const SteamUtilTimeSpan spans[] = {
        {"second", 1},
        {"minute", 60},
        {"hour", 60 * 60},
        {"day", 60 * 60 * 24},
        {"week", 60 * 60 * 24 * 7},
        {"month", 60 * 60 * 24 * 30},
        {"year", 60 * 60 * 24 * 365},
        {NULL, 0}
    };

    span /= G_TIME_SPAN_SECOND;

    for (i = 1; spans[i].name != NULL; i++) {
        if (span < spans[i].span) {
            span /= spans[--i].span;
            break;
        }

        if (G_UNLIKELY(spans[i + 1].name == NULL)) {
            span /= spans[i].span;
            break;
        }
    }

    str = g_strdup_printf("%" G_GINT64_FORMAT " %s%s", span, spans[i].name,
                          ((span > 1) ? "s" : ""));

    return str;
}

gchar *
steam_util_time_since_utc(gint64 timestamp)
{
    GDateTime *beg;
    GDateTime *end;
    GTimeSpan spn;

    beg = g_date_time_new_from_unix_utc(timestamp);
    end = g_date_time_new_now_utc();
    spn = g_date_time_difference(end, beg);

    g_date_time_unref(beg);
    g_date_time_unref(end);

    if (G_UNLIKELY(spn < 0)) {
        spn = -spn;
    }

    return steam_util_time_span_str(spn);
}

gchar *
steam_util_ustrchr(const gchar *str, gchar chr)
{
    gchar qc;
    gsize cs;
    gsize i;
    gsize ssz;
    gssize j;

    if (G_UNLIKELY(str == NULL)) {
        return NULL;
    }

    ssz = strlen(str);

    for (qc = i = 0; i < ssz; i++) {
        if ((qc == 0) && (str[i] == chr)) {
            return (gchar *) str + i;
        }

        if ((str[i] != '"') && (str[i] != '\'')) {
            continue;
        }

        if ((qc != 0) && (str[i] != qc)) {
            continue;
        }

        for (cs = 0, j = i - 1; (j >= 0) && (str[j] == '\\'); j--, cs++);

        if ((cs % 2) == 0) {
            qc = (qc == 0) ? str[i] : 0;
        }
    }

    return NULL;
}
