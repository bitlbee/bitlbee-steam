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

#ifndef _STEAM_AUTH_H
#define _STEAM_AUTH_H

#include <glib.h>
#include <gmp.h>

typedef struct _SteamAuth SteamAuth;

struct _SteamAuth
{
    mpz_t mod;
    mpz_t exp;

    gchar *time;
    gchar *esid;
    gchar *cgid;
    gchar *curl;
};


SteamAuth *steam_auth_new(void);

void steam_auth_free(SteamAuth *auth);

void steam_auth_captcha(SteamAuth *auth, const gchar *cgid);

void steam_auth_email(SteamAuth *auth, const gchar *esid);

gboolean steam_auth_key_mod(SteamAuth *auth, const gchar *mod);

gboolean steam_auth_key_exp(SteamAuth *auth, const gchar *exp);

gchar *steam_auth_key_encrypt(SteamAuth *auth, const gchar *str);

#endif /* _STEAM_AUTH_H */
