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

#ifndef _STEAM_FRIEND_H
#define _STEAM_FRIEND_H

#include <bitlbee.h>

#define STEAM_FRIEND_ID_NEW(u, t, i, n) ((gint64) ( \
         ((gint32) n)        | \
        (((gint64) i) << 32) | \
        (((gint64) t) << 52) | \
        (((gint64) u) << 56)   \
    ))

#define STEAM_FRIEND_ID_INSTANCE(id) ((gint32) ( \
        (((gint64) id) >> 32) & 0x0FFFFF \
    ))

#define STEAM_FRIEND_ID_NUMBER(id) ((gint32) ( \
        ((gint64) id) & 0xFFFFFFFF \
    ))

#define STEAM_FRIEND_ID_TYPE(id) ((SteamFriendIdType) ( \
        (id >> 52) & 0x0F \
    ))

#define STEAM_FRIEND_ID_UNIVERSE(id) ((SteamFriendIdUniverse) ( \
        ((gint64) id) >> 56 \
    ))

typedef enum   _SteamFriendAction     SteamFriendAction;
typedef enum   _SteamFriendIdType     SteamFriendIdType;
typedef enum   _SteamFriendIdUniverse SteamFriendIdUniverse;
typedef enum   _SteamFriendRelation   SteamFriendRelation;
typedef enum   _SteamFriendState      SteamFriendState;
typedef struct _SteamFriend           SteamFriend;
typedef struct _SteamFriendSummary    SteamFriendSummary;
typedef struct _SteamFriendId         SteamFriendId;

enum _SteamFriendAction
{
    STEAM_FRIEND_ACTION_REMOVE    = 0,
    STEAM_FRIEND_ACTION_IGNORE    = 1,
    STEAM_FRIEND_ACTION_REQUEST   = 2,
    STEAM_FRIEND_ACTION_ADD       = 3,
    STEAM_FRIEND_ACTION_REQUESTED = 4,

    STEAM_FRIEND_ACTION_NONE,
    STEAM_FRIEND_ACTION_LAST
};

enum _SteamFriendIdType
{
    STEAM_FRIEND_ID_TYPE_INVALID        = 0,
    STEAM_FRIEND_ID_TYPE_INDIVIDUAL     = 1,
    STEAM_FRIEND_ID_TYPE_MULTISEAT      = 2,
    STEAM_FRIEND_ID_TYPE_GAMESERVER     = 3,
    STEAM_FRIEND_ID_TYPE_ANONGAMESERVER = 4,
    STEAM_FRIEND_ID_TYPE_PENDING        = 5,
    STEAM_FRIEND_ID_TYPE_CONTENTSERVER  = 6,
    STEAM_FRIEND_ID_TYPE_CLAN           = 7,
    STEAM_FRIEND_ID_TYPE_CHAT           = 8,
    STEAM_FRIEND_ID_TYPE_SUPERSEEDER    = 9,
    STEAM_FRIEND_ID_TYPE_ANONUSER       = 10
};

enum _SteamFriendIdUniverse
{
    STEAM_FRIEND_ID_UNIVERSE_UNKNOWN  = 0,
    STEAM_FRIEND_ID_UNIVERSE_PUBLIC   = 1,
    STEAM_FRIEND_ID_UNIVERSE_BETA     = 2,
    STEAM_FRIEND_ID_UNIVERSE_INTERNAL = 3,
    STEAM_FRIEND_ID_UNIVERSE_DEV      = 4,
    STEAM_FRIEND_ID_UNIVERSE_RC       = 5
};

enum _SteamFriendRelation
{
    STEAM_FRIEND_RELATION_FRIEND = 0,
    STEAM_FRIEND_RELATION_IGNORE
};

enum _SteamFriendState
{
    STEAM_FRIEND_STATE_OFFLINE = 0,
    STEAM_FRIEND_STATE_ONLINE  = 1,
    STEAM_FRIEND_STATE_BUSY    = 2,
    STEAM_FRIEND_STATE_AWAY    = 3,
    STEAM_FRIEND_STATE_SNOOZE  = 4,
    STEAM_FRIEND_STATE_TRADE   = 5,
    STEAM_FRIEND_STATE_PLAY    = 6,

    STEAM_FRIEND_STATE_LAST
};

struct _SteamFriend
{
    bee_user_t *buser;

    gchar *game;
    gchar *server;

    gint64 lview;
};

struct _SteamFriendId
{
    SteamFriendIdType     type;
    SteamFriendIdUniverse universe;

    struct
    {
        gchar  *s;
        gint64  i;
    } steam;

    struct
    {
        gchar  *s;
        gint64  i;
    } commu;
};

struct _SteamFriendSummary
{
    SteamFriendState    state;
    SteamFriendRelation relation;
    SteamFriendAction   action;

    SteamFriendId *id;

    gchar *nick;
    gchar *fullname;
    gchar *game;
    gchar *server;

    gint64 lmesg;
    gint64 lview;
};


SteamFriend *steam_friend_new(bee_user_t *bu);

void steam_friend_free(SteamFriend *frnd);

SteamFriendId *steam_friend_id_new(gint64 id);

SteamFriendId *steam_friend_id_new_str(const gchar *id);

SteamFriendId *steam_friend_id_dup(SteamFriendId *id);

void steam_friend_id_free(SteamFriendId *id);

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...);

void steam_friend_chans_umode(SteamFriend *frnd, gint mode);

SteamFriendSummary *steam_friend_summary_new(gint64 id);

SteamFriendSummary *steam_friend_summary_new_str(const gchar *id);

void steam_friend_summary_free(SteamFriendSummary *smry);

const gchar *steam_friend_state_str(SteamFriendState state);

SteamFriendState steam_friend_state_from_str(const gchar *state);

gint steam_friend_user_mode(gchar *mode);

#endif /* _STEAM_FRIEND_H */
