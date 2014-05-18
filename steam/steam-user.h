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

#ifndef _STEAM_USER_H
#define _STEAM_USER_H

#include <bitlbee.h>
#include <glib.h>


/**
 * Create a new 64-bit SteamID.
 *
 * @param u The #SteamUserIdUni.
 * @param t The #SteamUserIdType.
 * @param i The instance (usually 1).
 * @param n The account number.
 *
 * @return The resulting 64-bit SteamID.
 **/
#define STEAM_USER_ID_NEW(u, t, i, n) ((gint64) ( \
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
#define STEAM_USER_ID_INSTANCE(id) ((gint32) ( \
        (((gint64) id) >> 32) & 0x0FFFFF \
    ))

/**
 * Get the 32-bit account number from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting 32-bit account number.
 **/
#define STEAM_USER_ID_NUMBER(id) ((gint32) ( \
        ((gint64) id) & 0xFFFFFFFF \
    ))

/**
 * Get the #SteamUserIdType from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting #SteamUserIdType.
 **/
#define STEAM_USER_ID_TYPE(id) ((SteamUserIdType) ( \
        (id >> 52) & 0x0F \
    ))

/**
 * Get the #SteamUserIdUni from a 64-bit SteamID.
 *
 * @param id The 64-bit SteamID.
 *
 * @return The resulting #SteamUserIdUni.
 **/
#define STEAM_USER_ID_UNI(id) ((SteamUserIdUni) ( \
        ((gint64) id) >> 56 \
    ))


/** The action of a #SteamUserInfo. **/
typedef enum _SteamUserAct SteamUserAct;

/** The type of #SteamUserId. **/
typedef enum _SteamUserIdType SteamUserIdType;

/** The universe of #SteamUserId. **/
typedef enum _SteamUserIdUni SteamUserIdUni;

/** The type of #SteamUserMsg. **/
typedef enum _SteamUserMsgType SteamUserMsgType;

/** The relation of a #SteamUserInfo. **/
typedef enum _SteamUserRel SteamUserRel;

/** The state of a #SteamUserInfo. **/
typedef enum _SteamUserState SteamUserState;

/** The structure for a Steam user. **/
typedef struct _SteamUser SteamUser;

/** The structure for representing a 64-bit SteamID. **/
typedef struct _SteamUserId SteamUserId;

/** The structure for Steam user information. **/
typedef struct _SteamUserInfo SteamUserInfo;

/** The structure for a Steam user message. **/
typedef struct _SteamUserMsg SteamUserMsg;


/**
 * The action of a #SteamUserInfo.
 **/
enum _SteamUserAct
{
    STEAM_USER_ACT_REMOVE    = 0, /** Removed **/
    STEAM_USER_ACT_IGNORE    = 1, /** Ignored **/
    STEAM_USER_ACT_REQUEST   = 2, /** Friendship request **/
    STEAM_USER_ACT_ADD       = 3, /** Added **/
    STEAM_USER_ACT_REQUESTED = 4, /** Friendship request **/

    STEAM_USER_ACT_NONE           /** None **/
};

/**
 * The type of a #SteamUserId.
 **/
enum _SteamUserIdType
{
    STEAM_USER_ID_TYPE_INVALID        = 0, /** Invalid **/
    STEAM_USER_ID_TYPE_INDIVIDUAL     = 1, /** Individual (user) **/
    STEAM_USER_ID_TYPE_MULTISEAT      = 2, /** Multiseat **/
    STEAM_USER_ID_TYPE_GAMESERVER     = 3, /** Game server **/
    STEAM_USER_ID_TYPE_ANONGAMESERVER = 4, /** Anonymous game server **/
    STEAM_USER_ID_TYPE_PENDING        = 5, /** Pending **/
    STEAM_USER_ID_TYPE_CONTENTSERVER  = 6, /** Content server **/
    STEAM_USER_ID_TYPE_CLAN           = 7, /** Clan or group **/
    STEAM_USER_ID_TYPE_CHAT           = 8, /** Chat **/
    STEAM_USER_ID_TYPE_SUPERSEEDER    = 9, /** P2P super seeder **/
    STEAM_USER_ID_TYPE_ANONUSER       = 10 /** Anonymous user **/
};

/**
 * The universe of a #SteamUserId.
 **/
enum _SteamUserIdUni
{
    STEAM_USER_ID_UNI_UNKNOWN  = 0, /** Unknown **/
    STEAM_USER_ID_UNI_PUBLIC   = 1, /** Public **/
    STEAM_USER_ID_UNI_BETA     = 2, /** Beta **/
    STEAM_USER_ID_UNI_INTERNAL = 3, /** Internal **/
    STEAM_USER_ID_UNI_DEV      = 4, /** Development **/
    STEAM_USER_ID_UNI_RC       = 5  /** Release candidate **/
};

/**
 * The type of #SteamUserMsg.
 **/
enum _SteamUserMsgType
{
    STEAM_USER_MSG_TYPE_SAYTEXT = 0,  /** Say text (default) **/
    STEAM_USER_MSG_TYPE_EMOTE,        /** Emote **/
    STEAM_USER_MSG_TYPE_LEFT_CONV,    /** Left conversation **/
    STEAM_USER_MSG_TYPE_RELATIONSHIP, /** Relationship **/
    STEAM_USER_MSG_TYPE_STATE,        /** State **/
    STEAM_USER_MSG_TYPE_TYPING,       /** Typing **/

    STEAM_USER_MSG_TYPE_UNKNOWN       /** Unknown **/
};

/**
 * The relation of a #SteamUserInfo.
 **/
enum _SteamUserRel
{
    STEAM_USER_REL_FRIEND = 0, /** Friend **/
    STEAM_USER_REL_IGNORE      /** Ignored **/
};

/**
 * The state of a #SteamUserInfo.
 **/
enum _SteamUserState
{
    STEAM_USER_STATE_OFFLINE = 0, /** Offline **/
    STEAM_USER_STATE_ONLINE  = 1, /** Online **/
    STEAM_USER_STATE_BUSY    = 2, /** Busy **/
    STEAM_USER_STATE_AWAY    = 3, /** Away **/
    STEAM_USER_STATE_SNOOZE  = 4, /** Snooze **/
    STEAM_USER_STATE_TRADE   = 5, /** Looking to trade **/
    STEAM_USER_STATE_PLAY    = 6  /** Looking to play **/
};

/**
 * The structure for a Steam user.
 **/
struct _SteamUser
{
    bee_user_t *buser; /** The #bee_user_t. **/

    gchar *game;       /** The game name or NULL. **/
    gchar *server;     /** The game server or NULL. **/

    gint64 vtime;      /** The last view timestamp (UTC). **/
};

/**
 * The structure for representing a 64-bit SteamID.
 **/
struct _SteamUserId
{
    SteamUserIdType type; /** The #SteamUserIdType. **/
    SteamUserIdUni  uni;  /** The #SteamUserIdUni. **/

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
 * The structure for Steam user information. 
 **/
struct _SteamUserInfo
{
    SteamUserId *id;      /** The #SteamUserId. **/

    SteamUserState state; /** The #SteamUserState. **/
    SteamUserRel   rel;   /** The #SteamUserRel. **/
    SteamUserAct   act;   /** The #SteamUserAct. **/

    gchar *nick;          /** The nickname. **/
    gchar *fullname;      /** The full name. **/
    gchar *game;          /** The game name or NULL. **/
    gchar *server;        /** The game server or NULL. **/

    gint64 mtime;         /** The last message timestamp (UTC). **/
    gint64 vtime;         /** The last view timestamp (UTC). **/
};

/**
 * The structure for a Steam user message.
 **/
struct _SteamUserMsg
{
    SteamUserMsgType  type;   /** The #SteamUserMsgType. **/
    SteamUserInfo    *info;   /** The #SteamUserInfo. **/

    gchar  *text;            /** The message text or NULL. **/
    gint64  time;            /** The message timestamp (UTC) or NULL **/
};



SteamUser *steam_user_new(bee_user_t *bu);

void steam_user_free(SteamUser *user);

gint steam_user_chan_mode(const gchar *mode);

void steam_user_chans_msg(SteamUser *user, const gchar *format, ...);

void steam_user_chans_umode(SteamUser *user, gint mode, gboolean override);

gint steam_user_chan_mode(const gchar *mode);

SteamUserId *steam_user_id_new(gint64 id);

SteamUserId *steam_user_id_new_str(const gchar *id);

SteamUserId *steam_user_id_dup(const SteamUserId *id);

void steam_user_id_free(SteamUserId *id);

SteamUserInfo *steam_user_info_new(gint64 id);

SteamUserInfo *steam_user_info_new_str(const gchar *id);

void steam_user_info_free(SteamUserInfo *info);

SteamUserMsg *steam_user_msg_new(gint64 id);

SteamUserMsg *steam_user_msg_new_str(const gchar *id);

void steam_user_msg_free(SteamUserMsg *msg);

const gchar *steam_user_msg_type_str(SteamUserMsgType type);

SteamUserMsgType steam_user_msg_type_from_str(const gchar *type);

const gchar *steam_user_state_str(SteamUserState state);

#endif /* _STEAM_USER_H */
