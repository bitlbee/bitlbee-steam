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

#ifndef _STEAM_ID_H
#define _STEAM_ID_H

#include "steam-glib.h"

#define STEAM_ID_CONSTANT(v) G_GINT64_CONSTANT(v)
#define STEAM_ID_FORMAT      G_GINT64_FORMAT
#define STEAM_ID_MODIFIER    G_GINT64_MODIFIER
#define STEAM_ID_STR_MAX     21
#define steam_id_hash        g_int64_hash
#define steam_id_equal       g_int64_equal

/**
 * Creates a new #SteamId.
 *
 * @param u The #SteamIdUniv.
 * @param t The #SteamIdType.
 * @param i The #SteamIdInst.
 * @param n The AccountID.
 *
 * @return The resulting #SteamId.
 **/
#define STEAM_ID_NEW(u, t, i, n) ((SteamId) ( \
         ((gint32) n)        |                \
        (((gint64) i) << 32) |                \
        (((gint64) t) << 52) |                \
        (((gint64) u) << 56)                  \
    ))

/**
 * Creates a new #SteamId from a string.
 *
 * @param s The string #SteamId.
 *
 * @return The resulting #SteamId.
 **/
#define STEAM_ID_NEW_STR(s) \
    g_ascii_strtoll(s, NULL, 10)

/**
 * Gets the string representation of a #SteamId.
 *
 * @param id The string #SteamId.
 * @param s  The string buffer.
 **/
#define STEAM_ID_STR(id, s) \
    g_sprintf(s, "%" STEAM_ID_FORMAT, (SteamId) id)

/**
 * Gets the string representation of a #SteamId AccountID.
 *
 * @param id The string #SteamId.
 * @param s  The string buffer.
 **/
#define STEAM_ID_ACCID_STR(id, s) \
    g_sprintf(s, "%" G_GINT32_FORMAT, STEAM_ID_ACCID(id))

/**
 * Gets the 32-bit AccountID from a #SteamId.
 *
 * @param id The #SteamId.
 *
 * @return The resulting AccountID.
 **/
#define STEAM_ID_ACCID(id) ((gint32) ( \
        ((SteamId) id) & 0xFFFFFFFF    \
    ))

/**
 * Gets the #SteamIdInst from a #SteamId.
 *
 * @param id The #SteamId.
 *
 * @return The resulting #SteamIdInst.
 **/
#define STEAM_ID_INST(id) ((SteamIdInst) ( \
        (((SteamId) id) >> 32) & 0x0FFFFF  \
    ))

/**
 * Gets the #SteamIdType from a #SteamId.
 *
 * @param id The #SteamId.
 *
 * @return The resulting #SteamIdType.
 **/
#define STEAM_ID_TYPE(id) ((SteamIdType) ( \
        (((SteamId) id) >> 52) & 0x0F      \
    ))

/**
 * Gets the #SteamIdUniv from a #SteamId.
 *
 * @param id The #SteamId.
 *
 * @return The resulting #SteamIdUniv.
 **/
#define STEAM_ID_UNIV(id) ((SteamIdUniv) ( \
        ((SteamId) id) >> 56               \
    ))


/** The instance of a #SteamId. **/
typedef enum _SteamIdInst SteamIdInst;

/** The type of #SteamId. **/
typedef enum _SteamIdType SteamIdType;

/** The universe of #SteamId. **/
typedef enum _SteamIdUniv SteamIdUniv;

/** The 64-bit SteamID. **/
typedef gint64 SteamId;


/**
 * The instance of a #SteamId.
 **/
enum _SteamIdInst
{
    STEAM_ID_INST_ALL     = 0, /** All **/
    STEAM_ID_INST_DESKTOP = 1, /** Desktop **/
    STEAM_ID_INST_CONSOLE = 2, /** Console **/
    STEAM_ID_INST_WEB     = 4  /** Web **/
};

/**
 * The type of a #SteamId.
 **/
enum _SteamIdType
{
    STEAM_ID_TYPE_INVALID        = 0, /** Invalid **/
    STEAM_ID_TYPE_INDIVIDUAL     = 1, /** Individual (user) **/
    STEAM_ID_TYPE_MULTISEAT      = 2, /** Multiseat **/
    STEAM_ID_TYPE_GAMESERVER     = 3, /** Game server **/
    STEAM_ID_TYPE_ANONGAMESERVER = 4, /** Anonymous game server **/
    STEAM_ID_TYPE_PENDING        = 5, /** Pending **/
    STEAM_ID_TYPE_CONTENTSERVER  = 6, /** Content server **/
    STEAM_ID_TYPE_CLAN           = 7, /** Clan or group **/
    STEAM_ID_TYPE_CHAT           = 8, /** Chat **/
    STEAM_ID_TYPE_SUPERSEEDER    = 9, /** P2P super seeder **/
    STEAM_ID_TYPE_ANONUSER       = 10 /** Anonymous user **/
};

/**
 * The universe of a #SteamId.
 **/
enum _SteamIdUniv
{
    STEAM_ID_UNIV_UNKNOWN  = 0, /** Unknown **/
    STEAM_ID_UNIV_PUBLIC   = 1, /** Public **/
    STEAM_ID_UNIV_BETA     = 2, /** Beta **/
    STEAM_ID_UNIV_INTERNAL = 3, /** Internal **/
    STEAM_ID_UNIV_DEV      = 4, /** Development **/
    STEAM_ID_UNIV_RC       = 5  /** Release candidate **/
};

#endif /* _STEAM_ID_H */
