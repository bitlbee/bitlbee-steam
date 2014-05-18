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

/** @file **/

#ifndef _STEAM_FRIEND_H
#define _STEAM_FRIEND_H

#include <bitlbee.h>
#include <glib.h>


/**
 * Create a new 64-bit SteamID.
 *
 * @param u The #SteamFriendIdUniverse.
 * @param t The #SteamFriendIdType.
 * @param i The instance (usually 1).
 * @param n The account number.
 *
 * @return The resulting 64-bit SteamID.
 **/
#define STEAM_FRIEND_ID_NEW(u, t, i, n) ((gint64) ( \
         ((gint32) n)        | \
        (((gint64) i) << 32) | \
        (((gint64) t) << 52) | \
        (((gint64) u) << 56)   \
    ))

/**
 * Get the 20-bit account instance from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting 20-bit account instance.
 **/
#define STEAM_FRIEND_ID_INSTANCE(id) ((gint32) ( \
        (((gint64) id) >> 32) & 0x0FFFFF \
    ))

/**
 * Get the 32-bit account number from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting 32-bit account number.
 **/
#define STEAM_FRIEND_ID_NUMBER(id) ((gint32) ( \
        ((gint64) id) & 0xFFFFFFFF \
    ))

/**
 * Get the #SteamFriendIdType from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting #SteamFriendIdType.
 **/
#define STEAM_FRIEND_ID_TYPE(id) ((SteamFriendIdType) ( \
        (id >> 52) & 0x0F \
    ))

/**
 * Get the #SteamFriendIdUniverse from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting #SteamFriendIdUniverse.
 **/
#define STEAM_FRIEND_ID_UNIVERSE(id) ((SteamFriendIdUniverse) ( \
        ((gint64) id) >> 56 \
    ))


/** The action of a #SteamFriendSummary. **/
typedef enum _SteamFriendAction SteamFriendAction;

/** The type of #SteamFriendId. **/
typedef enum _SteamFriendIdType SteamFriendIdType;

/** The universe of #SteamFriendId. **/
typedef enum _SteamFriendIdUniverse SteamFriendIdUniverse;

/** The relation of a #SteamFriendSummary. **/
typedef enum _SteamFriendRelation SteamFriendRelation;

/** The state of a #SteamFriendSummary. **/
typedef enum _SteamFriendState SteamFriendState;

/** The structure for a Steam friend. **/
typedef struct _SteamFriend SteamFriend;

/** The structure for representing a SteamID. **/
typedef struct _SteamFriendId SteamFriendId;

/** The structure for Steam friend information. **/
typedef struct _SteamFriendSummary SteamFriendSummary;


/**
 * The action of a #SteamFriendSummary.
 **/
enum _SteamFriendAction
{
    STEAM_FRIEND_ACTION_REMOVE    = 0, /** Removed **/
    STEAM_FRIEND_ACTION_IGNORE    = 1, /** Ignored **/
    STEAM_FRIEND_ACTION_REQUEST   = 2, /** Friendship request **/
    STEAM_FRIEND_ACTION_ADD       = 3, /** Added **/
    STEAM_FRIEND_ACTION_REQUESTED = 4, /** Friendship request **/

    STEAM_FRIEND_ACTION_NONE,          /** None **/
    STEAM_FRIEND_ACTION_LAST           /** Last **/
};

/**
 * The type of #SteamFriendId.
 **/
enum _SteamFriendIdType
{
    STEAM_FRIEND_ID_TYPE_INVALID        = 0, /** Invalid **/
    STEAM_FRIEND_ID_TYPE_INDIVIDUAL     = 1, /** Individual (user) **/
    STEAM_FRIEND_ID_TYPE_MULTISEAT      = 2, /** Multiseat **/
    STEAM_FRIEND_ID_TYPE_GAMESERVER     = 3, /** Game server **/
    STEAM_FRIEND_ID_TYPE_ANONGAMESERVER = 4, /** Anonymous game server **/
    STEAM_FRIEND_ID_TYPE_PENDING        = 5, /** Pending **/
    STEAM_FRIEND_ID_TYPE_CONTENTSERVER  = 6, /** Content server **/
    STEAM_FRIEND_ID_TYPE_CLAN           = 7, /** Clan or group **/
    STEAM_FRIEND_ID_TYPE_CHAT           = 8, /** Chat **/
    STEAM_FRIEND_ID_TYPE_SUPERSEEDER    = 9, /** P2P super seeder **/
    STEAM_FRIEND_ID_TYPE_ANONUSER       = 10 /** Anonymous user **/
};

/**
 * The universe of #SteamFriendId.
 **/
enum _SteamFriendIdUniverse
{
    STEAM_FRIEND_ID_UNIVERSE_UNKNOWN  = 0, /** Unknown **/
    STEAM_FRIEND_ID_UNIVERSE_PUBLIC   = 1, /** Public **/
    STEAM_FRIEND_ID_UNIVERSE_BETA     = 2, /** Beta **/
    STEAM_FRIEND_ID_UNIVERSE_INTERNAL = 3, /** Internal **/
    STEAM_FRIEND_ID_UNIVERSE_DEV      = 4, /** Development **/
    STEAM_FRIEND_ID_UNIVERSE_RC       = 5  /** Release candidate **/
};

/**
 * The relation of a #SteamFriendSummary.
 **/
enum _SteamFriendRelation
{
    STEAM_FRIEND_RELATION_FRIEND = 0, /** Friend **/
    STEAM_FRIEND_RELATION_IGNORE      /** Ignored **/
};

/**
 * The state of a #SteamFriendSummary.
 **/
enum _SteamFriendState
{
    STEAM_FRIEND_STATE_OFFLINE = 0, /** Offline **/
    STEAM_FRIEND_STATE_ONLINE  = 1, /** Online **/
    STEAM_FRIEND_STATE_BUSY    = 2, /** Busy **/
    STEAM_FRIEND_STATE_AWAY    = 3, /** Away **/
    STEAM_FRIEND_STATE_SNOOZE  = 4, /** Snooze **/
    STEAM_FRIEND_STATE_TRADE   = 5, /** Looking to trade **/
    STEAM_FRIEND_STATE_PLAY    = 6, /** Looking to play **/

    STEAM_FRIEND_STATE_LAST         /** Last **/
};

/**
 * The main structure used for Steam friends.
 **/
struct _SteamFriend
{
    bee_user_t *buser; /** The #bee_user_t. **/

    gchar *game;       /** The game name or NULL. **/
    gchar *server;     /** The game server or NULL. **/

    gint64 lview;      /** The last view timestamp (UTC). **/
};

/**
 * The structure used for representing a 64-bit SteamID.
 **/
struct _SteamFriendId
{
    SteamFriendIdType     type;     /** The #SteamFriendIdType. **/
    SteamFriendIdUniverse universe; /** The #SteamFriendIdUniverse. **/

    /**
     * The substructure used for representing a 64-bit SteamID.
     **/
    struct
    {
        gchar  *s; /** The string form of the SteamID. **/
        gint64  i; /** The integer form of the SteamID. **/
    } steam;

    /**
     * The structure used for representing a 32-bit Steam CommunityID.
     **/
    struct
    {
        gchar  *s; /** The string form of the CommunityID. **/
        gint64  i; /** The integer form of the CommunityID. **/
    } commu;
};

/**
 * The structure used for holding information about a Steam friend.
 **/
struct _SteamFriendSummary
{
    SteamFriendState    state;    /** The #SteamFriendState. **/
    SteamFriendRelation relation; /** The #SteamFriendRelation. **/
    SteamFriendAction   action;   /** The #SteamFriendAction. **/

    SteamFriendId *id;            /** The #SteamFriendId. **/

    gchar *nick;                  /** The nickname. **/
    gchar *fullname;              /** The full name. **/
    gchar *game;                  /** The game name or NULL. **/
    gchar *server;                /** The game server or NULL. **/

    gint64 lmesg;                 /** The last message timestamp (UTC). **/
    gint64 lview;                 /** The last view timestamp (UTC). **/
};


SteamFriend *steam_friend_new(bee_user_t *bu);

void steam_friend_free(SteamFriend *frnd);

SteamFriendId *steam_friend_id_new(gint64 id);

SteamFriendId *steam_friend_id_new_str(const gchar *id);

SteamFriendId *steam_friend_id_dup(SteamFriendId *id);

void steam_friend_id_free(SteamFriendId *id);

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...);

void steam_friend_chans_umode(SteamFriend *frnd, gint mode, gboolean override);

SteamFriendSummary *steam_friend_summary_new(gint64 id);

SteamFriendSummary *steam_friend_summary_new_str(const gchar *id);

void steam_friend_summary_free(SteamFriendSummary *smry);

const gchar *steam_friend_state_str(SteamFriendState state);

SteamFriendState steam_friend_state_from_str(const gchar *state);

gint steam_friend_user_mode(gchar *mode);

#endif /* _STEAM_FRIEND_H */
