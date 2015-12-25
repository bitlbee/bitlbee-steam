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

#ifndef _STEAM_USER_H_
#define _STEAM_USER_H_

/**
 * SECTION:user
 * @section_id: steam-user
 * @short_description: <filename>steam-user.h</filename>
 * @title: JSON Utilities
 *
 * The JSON utilities.
 */

#include <bitlbee.h>

#include "steam-glib.h"
#include "steam-id.h"

typedef struct _SteamUser SteamUser;
typedef struct _SteamUserInfo SteamUserInfo;
typedef struct _SteamUserMsg SteamUserMsg;

/**
 * SteamUserAct:
 * @STEAM_USER_ACT_REMOVE: Removed.
 * @STEAM_USER_ACT_IGNORE: Ignored.
 * @STEAM_USER_ACT_REQUEST: Friendship request.
 * @STEAM_USER_ACT_ADD: Added.
 * @STEAM_USER_ACT_REQUESTED: Requested friendship.
 * @STEAM_USER_ACT_NONE: None.
 *
 * The #SteamUserInfo actions.
 */
typedef enum
{
    STEAM_USER_ACT_REMOVE = 0,
    STEAM_USER_ACT_IGNORE = 1,
    STEAM_USER_ACT_REQUEST = 2,
    STEAM_USER_ACT_ADD = 3,
    STEAM_USER_ACT_REQUESTED = 4,

    STEAM_USER_ACT_NONE
} SteamUserAct;

/**
 * SteamUserMsgType:
 * @STEAM_USER_MSG_TYPE_SAYTEXT: Say text.
 * @STEAM_USER_MSG_TYPE_EMOTE: Emote.
 * @STEAM_USER_MSG_TYPE_LEFT_CONV: Left conversation.
 * @STEAM_USER_MSG_TYPE_RELATIONSHIP: Relationship.
 * @STEAM_USER_MSG_TYPE_STATE: State.
 * @STEAM_USER_MSG_TYPE_TYPING: Typing.
 * @STEAM_USER_MSG_TYPE_MY_SAYTEXT: My say text.
 * @STEAM_USER_MSG_TYPE_MY_EMOTE: My emote.
 * @STEAM_USER_MSG_TYPE_UNKNOWN: Unknown.
 *
 * The #SteamUserMsg types.
 */
typedef enum
{
    STEAM_USER_MSG_TYPE_SAYTEXT = 0,
    STEAM_USER_MSG_TYPE_EMOTE,
    STEAM_USER_MSG_TYPE_LEFT_CONV,
    STEAM_USER_MSG_TYPE_RELATIONSHIP,
    STEAM_USER_MSG_TYPE_STATE,
    STEAM_USER_MSG_TYPE_TYPING,
    STEAM_USER_MSG_TYPE_MY_SAYTEXT,
    STEAM_USER_MSG_TYPE_MY_EMOTE,

    STEAM_USER_MSG_TYPE_UNKNOWN
} SteamUserMsgType;

/**
 * SteamUserRel:
 * @STEAM_USER_REL_FRIEND: Friend.
 * @STEAM_USER_REL_IGNORE: Ignored.
 *
 * The #SteamUserInfo relationships.
 */
typedef enum
{
    STEAM_USER_REL_FRIEND = 0,
    STEAM_USER_REL_IGNORE
} SteamUserRel;

/**
 * SteamUserState:
 * @STEAM_USER_STATE_OFFLINE: Offline.
 * @STEAM_USER_STATE_ONLINE: Online.
 * @STEAM_USER_STATE_BUSY: Busy.
 * @STEAM_USER_STATE_AWAY: Away.
 * @STEAM_USER_STATE_SNOOZE: Snooze.
 * @STEAM_USER_STATE_TRADE: Trade.
 * @STEAM_USER_STATE_PLAY: Play.
 *
 * The #SteamUserInfo states.
 */
typedef enum
{
    STEAM_USER_STATE_OFFLINE = 0,
    STEAM_USER_STATE_ONLINE = 1,
    STEAM_USER_STATE_BUSY = 2,
    STEAM_USER_STATE_AWAY = 3,
    STEAM_USER_STATE_SNOOZE = 4,
    STEAM_USER_STATE_TRADE = 5,
    STEAM_USER_STATE_PLAY = 6
} SteamUserState;

/**
 * SteamUserFlags:
 * @STEAM_USER_FLAG_WEB: Using a web client.
 * @STEAM_USER_FLAG_MOBILE: Using a mobile client.
 * @STEAM_USER_FLAG_BIGPIC: Using Big Picture mode.
 *
 * The #SteamUserInfo flags.
 */
typedef enum
{
    STEAM_USER_FLAG_WEB = 1 << 8,
    STEAM_USER_FLAG_MOBILE = 1 << 9,
    STEAM_USER_FLAG_BIGPIC = 1 << 10
} SteamUserFlags;

/**
 * SteamUser:
 * @buser: The #bee_user.
 * @game: The game name or #NULL.
 * @server: The game server or #NULL.
 * @vtime: The last view timestamp (UTC).
 *
 * Represents a Steam user.
 */
struct _SteamUser
{
    bee_user_t *buser;
    gchar *game;
    gchar *server;
    gint64 vtime;
};

/**
 * SteamUserInfo:
 * @id: The #SteamId.
 * @nicks: The #GSList of prior nicknames.
 * @state: The #SteamUserState.
 * @flags: The #SteamUserFlags.
 * @rel: The #SteamUserRel.
 * @act: The #SteamUserAct.
 * @nick: The nickname.
 * @fullname: The full name.
 * @game: The game name or #NULL.
 * @server: The game server or #NULL.
 * @profile: The profile URL or #NULL.
 * @ltime: The last logoff timestamp (UTC).
 * @vtime: The last view timestamp (UTC).
 * @unread: The unread message count.
 *
 * Represents Steam user information.
 */
struct _SteamUserInfo
{
    SteamId id;
    GSList *nicks;

    SteamUserState state;
    SteamUserFlags flags;
    SteamUserRel rel;
    SteamUserAct act;

    gchar *nick;
    gchar *fullname;
    gchar *game;
    gchar *server;
    gchar *profile;

    gint64 ltime;
    gint64 vtime;
    guint unread;
};

/**
 * SteamUserMsg:
 * @type: The #SteamUserMsgType.
 * @info: The #SteamUserInfo.
 * @text: The message text or #NULL.
 * @time: The message timestamp (UTC).
 *
 * Represents a steam user messages.
 */
struct _SteamUserMsg
{
    SteamUserMsgType type;
    SteamUserInfo *info;

    gchar *text;
    gint64 time;
};

/**
 * steam_user_new:
 * @bu: The #bee_user.
 *
 * Creates a new #SteamUser. The returned #SteamUser should be freed
 * with #steam_user_free() when no longer needed.
 *
 * Returns: The #SteamUser.
 */
SteamUser *
steam_user_new(bee_user_t *bu);

/**
 * steam_user_free:
 * @user: The #SteamUser.
 *
 * Frees all memory used by the #SteamUser.
 */
void
steam_user_free(SteamUser *user);

/**
 * steam_user_chans_msg:
 * @user: The #SteamUser.
 * @format: The format string.
 * @...: The arguments for the format string.
 *
 * Sends a message to all channels which the #SteamUser is occupying
 * with the sender being the #SteamUser.
 */
void
steam_user_chans_msg(SteamUser *user, const gchar *fmt, ...)
                     G_GNUC_PRINTF(2, 3);

/**
 * steam_user_flags_str:
 * @flags: The #SteamUserFlags.
 *
 * Gets the string representation of the #SteamUserFlags. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The string representation or #NULL on error.
 */
gchar *
steam_user_flags_str(SteamUserFlags flags);

/**
 * steam_user_info_new:
 * @id: The #SteamId.
 *
 * Creates a new #SteamUserInfo. The returned #SteamUserInfo should be
 * freed with #steam_user_info_free() when no longer needed.
 *
 * Returns: The #SteamUserInfo or #NULL on error.
 */
SteamUserInfo *
steam_user_info_new(SteamId id);

/**
 * steam_user_info_free:
 * @info: The #SteamUserInfo.
 *
 * Frees all memory used by the #SteamUserInfo.
 */
void
steam_user_info_free(SteamUserInfo *info);


/**
 * steam_user_msg_new:
 * @id: The #SteamId.
 *
 * Creates a new #SteamUserMsg. The returned #SteamUserMsg should be
 * freed with #steam_user_msg_free() when no longer needed.
 *
 * Returns: The #SteamUserMsg.
 */
SteamUserMsg *
steam_user_msg_new(SteamId id);

/**
 * steam_user_msg_free:
 * @msg: The #SteamUserMsg.
 *
 * Frees all memory used by the #SteamUserMsg.
 */
void
steam_user_msg_free(SteamUserMsg *msg);

/**
 * steam_user_msg_type_str:
 * @type: The #SteamUserMsgType.
 *
 * Gets the string representation of the #SteamUserMsgType.
 *
 * Returns: The string representation or #NULL on error.
 */
const gchar *
steam_user_msg_type_str(SteamUserMsgType type);

/**
 * steam_user_msg_type_from_str:
 * @type: The string.
 *
 * Gets the #SteamUserMsgType value of the string.
 *
 * Returns: The #SteamUserMsgType value.
 */
SteamUserMsgType
steam_user_msg_type_from_str(const gchar *type);

/**
 * steam_user_state_str:
 * @state: The #SteamUserState.
 *
 * Gets the string representation of the #SteamUserState.
 *
 * Returns: The string representation or #NULL on error.
 */
const gchar *
steam_user_state_str(SteamUserState state);

#endif /* _STEAM_USER_H_ */
