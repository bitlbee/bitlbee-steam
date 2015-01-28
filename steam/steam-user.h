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

#ifndef _STEAM_USER_H
#define _STEAM_USER_H

#include <bitlbee.h>
#include <glib.h>

#include "steam-id.h"


/** The action of a #SteamUserInfo. **/
typedef enum _SteamUserAct SteamUserAct;

/** The type of #SteamUserMsg. **/
typedef enum _SteamUserMsgType SteamUserMsgType;

/** The relation of a #SteamUserInfo. **/
typedef enum _SteamUserRel SteamUserRel;

/** The state of a #SteamUserInfo. **/
typedef enum _SteamUserState SteamUserState;

/** The flags of #SteamUserInfo. **/
typedef enum _SteamUserFlags SteamUserFlags;

/** The structure for a Steam user. **/
typedef struct _SteamUser SteamUser;

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
 * The flags of #SteamUserInfo.
 **/
enum _SteamUserFlags
{
    STEAM_USER_FLAG_WEB    = 1 << 8, /** Using web client **/
    STEAM_USER_FLAG_MOBILE = 1 << 9, /** Using mobile client **/
    STEAM_USER_FLAG_BIGPIC = 1 << 10 /** Using Big Picture **/
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
 * The structure for Steam user information.
 **/
struct _SteamUserInfo
{
    SteamId  id;          /** The #SteamId. **/
    GSList  *nicks;       /** The #GSList of prior nicknames. */

    SteamUserState state; /** The #SteamUserState. **/
    SteamUserFlags flags; /** The #SteamUserFlags. **/
    SteamUserRel   rel;   /** The #SteamUserRel. **/
    SteamUserAct   act;   /** The #SteamUserAct. **/

    gchar *nick;          /** The nickname. **/
    gchar *fullname;      /** The full name. **/
    gchar *game;          /** The game name or NULL. **/
    gchar *server;        /** The game server or NULL. **/
    gchar *profile;       /** The profile URL or NULL. **/

    gint64 ltime;         /** The last logoff timestamp (UTC). **/
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

    gchar  *text;             /** The message text or NULL. **/
    gint64  time;             /** The message timestamp (UTC) or NULL **/
};


SteamUser *steam_user_new(bee_user_t *bu);

void steam_user_free(SteamUser *user);

void steam_user_chans_msg(SteamUser *user, const gchar *fmt, ...)
    G_GNUC_PRINTF(2, 3);

gchar *steam_user_flags_str(SteamUserFlags flags);

SteamUserInfo *steam_user_info_new(SteamId id);

void steam_user_info_free(SteamUserInfo *info);

SteamUserMsg *steam_user_msg_new(SteamId id);

void steam_user_msg_free(SteamUserMsg *msg);

const gchar *steam_user_msg_type_str(SteamUserMsgType type);

SteamUserMsgType steam_user_msg_type_from_str(const gchar *type);

const gchar *steam_user_state_str(SteamUserState state);

#endif /* _STEAM_USER_H */
