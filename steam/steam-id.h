/*
 * Copyright 2012-2016 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_ID_H_
#define _STEAM_ID_H_

/**
 * SECTION:id
 * @section_id: steam-id
 * @short_description: <filename>steam-id.h</filename>
 * @title: Steam Identifier
 *
 * The Steam identifier utilities.
 */

#include "steam-glib.h"

/**
 * STEAM_ID_FORMAT:
 *
 * The format specifier for printing and scanning a #SteamId.
 */
#define STEAM_ID_FORMAT  G_GINT64_FORMAT

/**
 * STEAM_ID_MODIFIER:
 *
 * The length modifier for printing a #SteamId.
 */
#define STEAM_ID_MODIFIER  G_GINT64_MODIFIER

/**
 * STEAM_ID_STRMAX:
 *
 * The maximum length, including a null-terminating character, of the
 * string representation of a #SteamId.
 */
#define STEAM_ID_STRMAX  21

/**
 * STEAM_TYPE_ID:
 *
 * The #GType of a #SteamId.
 */
#define STEAM_TYPE_ID  G_TYPE_INT64

/**
 * steam_id_equal:
 *
 * Compares the values of two #SteamId's for equality. See
 * #g_int64_equal.
 */
#define steam_id_equal  g_int64_equal

/**
 * steam_id_hash:
 *
 * Converts a pointer to a #SteamId hash value. See #g_int64_hash.
 */
#define steam_id_hash  g_int64_hash

/**
 * FB_ID_CONSTANT:
 * @v: The value.
 *
 * Inserts a literal #SteamId into source code.
 *
 * Return: The literal #SteamId value.
 */
#define STEAM_ID_CONSTANT(v)  G_GINT64_CONSTANT(v)

/**
 * STEAM_ID_NEW:
 * @u: The #SteamIdUniv.
 * @t: The #SteamIdType.
 * @i: The #SteamIdInst.
 * @n: The AccountID.
 *
 * Creates a new #SteamId.
 *
 * Returns: The resulting #SteamId.
 */
#define STEAM_ID_NEW(u, t, i, n) ((SteamId) ( \
         ((gint32) n) | \
        (((gint64) i) << 32) | \
        (((gint64) t) << 52) | \
        (((gint64) u) << 56) \
    ))

/**
 * STEAM_ID_NEW_STR:
 * @s: The string #SteamId.
 *
 * Creates a new #SteamId from a string.
 *
 * Returns: The resulting #SteamId.
 */
#define STEAM_ID_NEW_STR(s) \
    g_ascii_strtoll(s, NULL, 10)

/**
 * STEAM_ID_STR:
 * @id: The string #SteamId.
 * @s: The string buffer.
 *
 * Gets the string representation of the #SteamId.
 */
#define STEAM_ID_STR(id, s) \
    g_sprintf(s, "%" STEAM_ID_FORMAT, (SteamId) id)

/**
 * STEAM_ID_ACCID_STR:
 * @id: The string #SteamId.
 * @s: The string buffer.
 *
 * Gets the string representation of the #SteamId AccountID.
 */
#define STEAM_ID_ACCID_STR(id, s) \
    g_sprintf(s, "%" G_GINT32_FORMAT, STEAM_ID_ACCID(id))

/**
 * STEAM_ID_ACCID:
 * @id: The #SteamId.
 *
 * Gets the 32-bit AccountID from the #SteamId.
 *
 * Returns: The resulting AccountID.
 */
#define STEAM_ID_ACCID(id) ((gint32) ( \
        ((SteamId) id) & 0xFFFFFFFF \
    ))

/**
 * STEAM_ID_INST:
 * @id: The #SteamId.
 *
 * Gets the #SteamIdInst from the #SteamId.
 *
 * Returns: The resulting #SteamIdInst.
 */
#define STEAM_ID_INST(id) ((SteamIdInst) ( \
        (((SteamId) id) >> 32) & 0x0FFFFF \
    ))

/**
 * STEAM_ID_TYPE:
 * @id: The #SteamId.
 *
 * Gets the #SteamIdType from the #SteamId.
 *
 * Returns: The resulting #SteamIdType.
 */
#define STEAM_ID_TYPE(id) ((SteamIdType) ( \
        (((SteamId) id) >> 52) & 0x0F \
    ))

/**
 * STEAM_ID_UNIV:
 * @id: The #SteamId.
 *
 * Gets the #SteamIdUniv from the #SteamId.
 *
 * Returns: The resulting #SteamIdUniv.
 */
#define STEAM_ID_UNIV(id) ((SteamIdUniv) ( \
        ((SteamId) id) >> 56 \
    ))

/**
 * SteamId:
 *
 * Represents a numeric Steam identifier.
 */
typedef gint64 SteamId;

/**
 * SteamIdInst:
 * @STEAM_ID_INST_ALL: All.
 * @STEAM_ID_INST_DESKTOP: Desktop.
 * @STEAM_ID_INST_CONSOLE: Console.
 * @STEAM_ID_INST_WEB: Web.
 *
 * The #SteamId instances.
 */
typedef enum
{
    STEAM_ID_INST_ALL = 0,
    STEAM_ID_INST_DESKTOP = 1,
    STEAM_ID_INST_CONSOLE = 2,
    STEAM_ID_INST_WEB = 4
} SteamIdInst;

/**
 * SteamIdType:
 * @STEAM_ID_TYPE_INVALID: Invalid/
 * @STEAM_ID_TYPE_INDIVIDUAL: Individual (user).
 * @STEAM_ID_TYPE_MULTISEAT: Multiseat.
 * @STEAM_ID_TYPE_GAMESERVER: Game server.
 * @STEAM_ID_TYPE_ANONGAMESERVER: Anonymous game server.
 * @STEAM_ID_TYPE_PENDING: Pending.
 * @STEAM_ID_TYPE_CONTENTSERVER: Content server.
 * @STEAM_ID_TYPE_CLAN: Clan or group.
 * @STEAM_ID_TYPE_CHAT: Chat.
 * @STEAM_ID_TYPE_SUPERSEEDER: P2P super seeder.
 * @STEAM_ID_TYPE_ANONUSER: Anonymous user.
 *
 * The #SteamId types.
 */
typedef enum
{
    STEAM_ID_TYPE_INVALID = 0,
    STEAM_ID_TYPE_INDIVIDUAL = 1,
    STEAM_ID_TYPE_MULTISEAT = 2,
    STEAM_ID_TYPE_GAMESERVER = 3,
    STEAM_ID_TYPE_ANONGAMESERVER = 4,
    STEAM_ID_TYPE_PENDING = 5,
    STEAM_ID_TYPE_CONTENTSERVER = 6,
    STEAM_ID_TYPE_CLAN = 7,
    STEAM_ID_TYPE_CHAT = 8,
    STEAM_ID_TYPE_SUPERSEEDER = 9,
    STEAM_ID_TYPE_ANONUSER = 10
} SteamIdType;

/**
 * SteamIdUniv:
 * @STEAM_ID_UNIV_UNKNOWN: Unknown.
 * @STEAM_ID_UNIV_PUBLIC: Public.
 * @STEAM_ID_UNIV_BETA: Beta.
 * @STEAM_ID_UNIV_INTERNAL: Internal.
 * @STEAM_ID_UNIV_DEV: Development.
 * @STEAM_ID_UNIV_RC: Release Candidate.
 *
 * The #SteamId universes.
 */
typedef enum
{
    STEAM_ID_UNIV_UNKNOWN = 0,
    STEAM_ID_UNIV_PUBLIC = 1,
    STEAM_ID_UNIV_BETA = 2,
    STEAM_ID_UNIV_INTERNAL = 3,
    STEAM_ID_UNIV_DEV = 4,
    STEAM_ID_UNIV_RC = 5
} SteamIdUniv;

#endif /* _STEAM_ID_H_ */
