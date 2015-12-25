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

#ifndef _STEAM_CRYPT_H_
#define _STEAM_CRYPT_H_

/**
 * SECTION:crypt
 * @section_id: steam-crypt
 * @short_description: <filename>steam-crypt.h</filename>
 * @title: Cryptography Utilities
 *
 * The cryptography utilities.
 */

#include "steam-glib.h"

/**
 * steam_crypt_rsa_enc:
 * @mod: The modulus.
 * @exp: The exponent.
 * @bytes: The #GByteArray.
 *
 * Encrypts the #GByteArray via an RSA public key modules and exponent.
 * The returned #GByteArray should be freed with #g_byte_array_free()
 * when no longer needed.
 *
 * Returns: The encrypted #GByteArray or #NULL on error.
 */
GByteArray *
steam_crypt_rsa_enc(const GByteArray *mod, const GByteArray *exp,
                    const GByteArray *bytes);

/**
 * steam_crypt_rsa_enc_str:
 * @mod: The hexadecimal modulus string.
 * @exp: The hexadecimal exponent string.
 * @str: The string.
 *
 * Encrypts the string via an RSA public key modulus and exponent. The
 * modulus and exponent must be valid hexadecimal strings. The return
 * string is encoded with base64 encoding. The returned string should
 * be freed with #g_free() when no longer needed.
 *
 * Returns: The base64 encoded string or #NULL on error.
 */
gchar *
steam_crypt_rsa_enc_str(const gchar *mod, const gchar *exp, const gchar *str);

#endif /* _STEAM_CRYPT_H_ */
