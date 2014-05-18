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

#include <gmp.h>
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
 * Gets the enumerator pointers from its value. The returned array
 * should be freed when no longer needed.
 *
 * @param enums The array of #SteamUtilEnum.
 * @param vals  The enumerator values.
 *
 * @return The enumerator pointer array.
 **/
gpointer *steam_util_enum_ptrs(const SteamUtilEnum *enums, guint vals)
{
    gpointer *ptrs;
    gsize     size;
    guint     i;
    guint     j;

    g_return_val_if_fail(enums != NULL, g_new0(gpointer, 0));

    for (size = 0, i = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val)
            size++;
    }

    ptrs = g_new0(gpointer, ++size);

    for (i = 0, j = 0; enums[i].ptr != NULL; i++) {
        if (vals & enums[i].val)
            ptrs[j++] = enums[i].ptr;
    }

    return ptrs;
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
 * Pads a string for PKCS (RSA) processing.
 *
 * @param op  The output integer.
 * @param mod The modulus integer.
 * @param str The string.
 **/
static void steam_util_rsa_pad(mpz_t op, mpz_t mod, const gchar *str)
{
    GRand *rand;
    gchar *buf;
    gsize  b;
    gsize  bsz;
    gsize  ssz;

    bsz = mpz_sizeinbase(mod, 16) / 2;
    ssz = strlen(str);

    if (bsz < (ssz + 11))
        return;

    rand = g_rand_new();
    buf  = g_new0(gchar, bsz);
    b    = bsz - ssz;

    memcpy(buf + b, str, ssz);

    for (b -= 2; b > 1; b--)
        buf[b] = g_rand_int_range(rand, 1, 255);

    buf[b] = 2;
    mpz_import(op, bsz, 1, sizeof buf[0], 0, 0, buf);

    g_free(buf);
    g_rand_free(rand);
}

/**
 * Converts a raw PKCS (RSA) string to a hexadecimal string. The
 * returned string should be freed with #g_free() when no longer
 * needed.
 *
 * @param str The raw string.
 * @param ssz The size of the string.
 * @param rsz The return location for the size of the return string.
 *
 * @return The converted hexadecimal string or NULL on error.
 **/
static gchar *steam_util_rsa_hexdec(const gchar *str, gsize ssz, gsize *rsz)
{
    static gchar *hex;

    GString  *ret;
    gboolean  hax;
    gchar    *pos;
    gchar     chh;
    gchar     chr;
    gsize     i;

    hex = "0123456789abcdef";
    ret = g_string_sized_new(ssz / 2);

    for (i = 0, hax = FALSE; i < ssz; i++, hax = !hax) {
        chh = g_ascii_tolower(str[i]);
        pos = strchr(hex, chh);
        chh = (pos != NULL) ? (pos - hex) : 0;

        if (hax) {
            chr |= chh & 0x0F;
            g_string_append_c(ret, chr);
        } else {
            chr = (chh << 4) & 0xF0;
        }
    }

    *rsz = ret->len;
    return g_string_free(ret, FALSE);
}

/**
 * Encrypts a string via PKCS (RSA). The returned string should be
 * freed with #g_free() when no longer needed.
 *
 * @param pkmod The PKCS (RSA) modulus.
 * @param pkexp The PKCS (RSA) exponent.
 * @param str   The string to encrypt.
 *
 * @return The encrypted string or NULL on error.
 **/
gchar *steam_util_rsa_encrypt(const gchar *pkmod, const gchar *pkexp,
                              const gchar *str)
{
    gchar *buf;
    gchar *ret;
    gsize  bsz;
    mpz_t  ip;
    mpz_t  op;
    mpz_t  mod;
    mpz_t  exp;

    g_return_val_if_fail(pkmod != NULL, NULL);
    g_return_val_if_fail(pkexp != NULL, NULL);
    g_return_val_if_fail(str   != NULL, NULL);

    mpz_init(ip);
    mpz_init(op);
    mpz_init(mod);
    mpz_init(exp);

    mpz_set_str(mod, pkmod, 16);
    mpz_set_str(exp, pkexp, 16);

    steam_util_rsa_pad(ip, mod, str);

#ifdef mpz_powm_sec
    mpz_powm_sec(op, ip, exp, mod);
#else
    mpz_powm(op, ip, exp, mod);
#endif

    bsz = mpz_sizeinbase(op, 16) + 2;
    buf = g_new0(gchar, bsz);

    mpz_get_str(buf, 16, op);
    ret = steam_util_rsa_hexdec(buf, bsz, &bsz);
    g_free(buf);

    buf = ret;
    ret = g_base64_encode((guchar *) buf, bsz);

    mpz_clear(exp);
    mpz_clear(mod);
    mpz_clear(op);
    mpz_clear(ip);
    g_free(buf);

    return ret;
}

/**
 * Gets the string representation of a timespan. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * @param span The #GTimeSpan.
 *
 * @return The string representation of a timespan.
 **/
gchar *steam_util_time_span_str(GTimeSpan span)
{
    gchar *str;
    guint  i;

    static const SteamUtilTimeSpan spans[] = {
        {"second", 1},
        {"minute", 60},
        {"hour",   60 * 60},
        {"day",    60 * 60 * 24},
        {"week",   60 * 60 * 24 * 7},
        {"month",  60 * 60 * 24 * 30},
        {"year",   60 * 60 * 24 * 365},
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

/**
 * Gets the string representation of a timespan since the given
 * timestamp. The returned string should be freed with #g_free() when
 * no longer needed.
 *
 * @param span The timestamp (UTC).
 *
 * @return The string representation of a timespan.
 **/
gchar *steam_util_time_since_utc(gint64 timestamp)
{
    GDateTime *beg;
    GDateTime *end;
    GTimeSpan  spn;

    beg = g_date_time_new_from_unix_utc(timestamp);
    end = g_date_time_new_now_utc();
    spn = g_date_time_difference(end, beg);

    g_date_time_unref(beg);
    g_date_time_unref(end);

    if (G_UNLIKELY(spn < 0))
        spn = -spn;

    return steam_util_time_span_str(spn);
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
