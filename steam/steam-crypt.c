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

#include <gcrypt.h>
#include <string.h>

#include "steam-crypt.h"
#include "steam-util.h"

/**
 * Encrypts a #GByteArray via an RSA public key modules and exponent.
 * The returned #GByteArray should be freed with #g_byte_array_free()
 * when no longer needed.
 *
 * @param mod   The modulus.
 * @param exp   The exponent.
 * @param bytes The #GByteArray.
 *
 * @return The encrypted #GByteArray or NULL on error.
 **/
GByteArray *steam_crypt_rsa_enc(const GByteArray *mod, const GByteArray *exp,
                                const GByteArray *bytes)
{
    GByteArray   *ret;
    gcry_mpi_t    mmpi;
    gcry_mpi_t    empi;
    gcry_mpi_t    dmpi;
    gcry_sexp_t   kata;
    gcry_sexp_t   data;
    gcry_sexp_t   cata;
    gcry_error_t  res;
    gsize         size;

    g_return_val_if_fail(mod   != NULL, NULL);
    g_return_val_if_fail(exp   != NULL, NULL);
    g_return_val_if_fail(bytes != NULL, NULL);

    mmpi = empi = dmpi = NULL;
    kata = data = cata = NULL;
    ret  = NULL;

    res  = gcry_mpi_scan(&mmpi, GCRYMPI_FMT_USG, mod->data,
                         mod->len, NULL);
    res |= gcry_mpi_scan(&empi, GCRYMPI_FMT_USG, exp->data,
                         exp->len, NULL);
    res |= gcry_mpi_scan(&dmpi, GCRYMPI_FMT_USG, bytes->data,
                         bytes->len, NULL);

    if (G_UNLIKELY(res != 0))
        goto finish;

    res  = gcry_sexp_build(&kata, NULL, "(public-key(rsa(n %m)(e %m)))",
                           mmpi, empi);
    res |= gcry_sexp_build(&data, NULL, "(data(flags pkcs1)(value %m))",
                           dmpi);

    if (G_UNLIKELY(res != 0))
        goto finish;

    res = gcry_pk_encrypt(&cata, data, kata);

    if (G_UNLIKELY(res != 0))
        goto finish;

    data = gcry_sexp_find_token(cata, "a", 0);

    if (G_UNLIKELY(data == NULL)) {
        g_warn_if_reached();
        goto finish;
    }

    gcry_mpi_release(dmpi);
    dmpi = gcry_sexp_nth_mpi(data, 1, GCRYMPI_FMT_USG);

    if (G_UNLIKELY(dmpi == NULL)) {
        g_warn_if_reached();
        goto finish;
    }

    ret = g_byte_array_new();
    g_byte_array_set_size(ret, mod->len);

    gcry_mpi_print(GCRYMPI_FMT_USG, ret->data, ret->len, &size, dmpi);

    g_warn_if_fail(size <= mod->len);
    g_byte_array_set_size(ret, size);

finish:
    gcry_sexp_release(cata);
    gcry_sexp_release(data);
    gcry_sexp_release(kata);

    gcry_mpi_release(dmpi);
    gcry_mpi_release(empi);
    gcry_mpi_release(mmpi);

    return ret;
}

/**
 * Encrypts a string via an RSA public key modulus and exponent. The
 * modulus and exponent must be valid hexadecimal strings. The return
 * string is encoded with base64 encoding. The returned string should
 * be freed with #g_free() when no longer needed.
 *
 * @param mod The hexadecimal modulus string.
 * @param exp The hexadecimal exponent string.
 * @param str The string.
 *
 * @return The base64 encoded string or NULL on error.
 **/
gchar *steam_crypt_rsa_enc_str(const gchar *mod, const gchar *exp,
                               const gchar *str)
{
    GByteArray *bytes;
    GByteArray *mytes;
    GByteArray *eytes;
    GByteArray *enc;
    gchar      *ret;

    g_return_val_if_fail(mod != NULL, NULL);
    g_return_val_if_fail(exp != NULL, NULL);
    g_return_val_if_fail(str != NULL, NULL);

    mytes = steam_util_str_hex2bytes(mod);

    if (G_UNLIKELY(mytes == NULL))
        return NULL;

    eytes = steam_util_str_hex2bytes(exp);

    if (G_UNLIKELY(eytes == NULL)) {
        g_byte_array_free(mytes, TRUE);
        return NULL;
    }

    bytes = g_byte_array_new();
    g_byte_array_append(bytes, (guint8*) str, strlen(str));
    enc = steam_crypt_rsa_enc(mytes, eytes, bytes);

    g_byte_array_free(bytes, TRUE);
    g_byte_array_free(eytes, TRUE);
    g_byte_array_free(mytes, TRUE);

    if (G_UNLIKELY(enc == NULL))
        return NULL;

    ret = g_base64_encode(enc->data, enc->len);
    g_byte_array_free(enc, TRUE);

    return ret;
}
