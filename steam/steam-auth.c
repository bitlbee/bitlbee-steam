/*
 * Copyright 2012-2013 James Geboski <jgeboski@gmail.com>
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

#include "steam-api.h"
#include "steam-auth.h"

SteamAuth *steam_auth_new(void)
{
    SteamAuth *auth;

    auth = g_new0(SteamAuth, 1);

    mpz_init(auth->mod);
    mpz_init(auth->exp);

    return auth;
}

void steam_auth_free(SteamAuth *auth)
{
    if (auth == NULL)
        return;

    mpz_clear(auth->exp);
    mpz_clear(auth->mod);

    g_free(auth->curl);
    g_free(auth->cgid);
    g_free(auth->esid);
    g_free(auth->time);
    g_free(auth);
}

void steam_auth_captcha(SteamAuth *auth, const gchar *cgid)
{
    g_return_if_fail(auth != NULL);

    if (cgid == NULL)
        return;

    g_free(auth->cgid);
    g_free(auth->curl);

    auth->cgid = g_strdup(cgid);

    if (cgid == NULL)
        return;

    auth->curl = g_strdup_printf("https://%s%s?gid=%s", STEAM_COM_HOST,
                                 STEAM_COM_PATH_CAPTCHA, cgid);
}

void steam_auth_email(SteamAuth *auth, const gchar *esid)
{
    g_return_if_fail(auth != NULL);

    if (esid == NULL)
        return;

    g_free(auth->esid);
    auth->esid = g_strdup(esid);
}

gboolean steam_auth_key_mod(SteamAuth *auth, const gchar *mod)
{
    g_return_val_if_fail(auth != NULL, FALSE);
    g_return_val_if_fail(mod  != NULL, FALSE);

    return (mpz_set_str(auth->mod, mod, 16) == 0);
}

gboolean steam_auth_key_exp(SteamAuth *auth, const gchar *exp)
{
    g_return_val_if_fail(auth != NULL, FALSE);
    g_return_val_if_fail(exp  != NULL, FALSE);

    return (mpz_set_str(auth->exp, exp, 16) == 0);
}

static void steam_auth_key_encrypt_pkcs1pad(mpz_t op, SteamAuth *auth,
                                            const gchar *str)
{
    GRand *rand;
    gchar *buf;
    gsize  b;
    gsize  bsz;
    gsize  ssz;

    bsz = mpz_sizeinbase(auth->mod, 16) / 2;
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

static gchar *steam_auth_key_encrypt_hexdec(const gchar *str, gsize ssz,
                                            gsize *rsz)
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

gchar *steam_auth_key_encrypt(SteamAuth *auth, const gchar *str)
{
    gchar *buf;
    gchar *ret;
    gsize  bsz;
    mpz_t  op;
    mpz_t  opr;

    g_return_val_if_fail(auth != NULL, NULL);
    g_return_val_if_fail(str  != NULL, NULL);

    mpz_inits(op, opr, NULL);
    steam_auth_key_encrypt_pkcs1pad(op, auth, str);
    mpz_powm_sec(opr, op, auth->exp, auth->mod);

    bsz = mpz_sizeinbase(opr, 16) + 2;
    buf = g_new0(gchar, bsz);

    mpz_get_str(buf, 16, opr);
    ret = steam_auth_key_encrypt_hexdec(buf, bsz, &bsz);
    g_free(buf);

    buf = ret;
    ret = g_base64_encode((guchar *) buf, bsz);

    mpz_clears(op, opr, NULL);
    g_free(buf);
    return ret;
}
