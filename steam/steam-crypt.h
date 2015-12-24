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

#ifndef _STEAM_CRYPT_H_
#define _STEAM_CRYPT_H_

#include "steam-glib.h"

GByteArray *
steam_crypt_rsa_enc(const GByteArray *mod, const GByteArray *exp,
                    const GByteArray *bytes);

gchar *
steam_crypt_rsa_enc_str(const gchar *mod, const gchar *exp, const gchar *str);

#endif /* _STEAM_CRYPT_H_ */
