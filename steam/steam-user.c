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

#include <string.h>

#include "steam-user.h"
#include "steam-util.h"

/**
 * Creates a new #SteamUser with a #bee_user_t. The returned #SteamUser
 * should be freed with #steam_user_free() when no longer needed.
 *
 * @param bu The #bee_user_t.
 *
 * @return The #SteamUser or NULL on error.
 **/
SteamUser *steam_user_new(bee_user_t *bu)
{
    SteamUser *user;

    user = g_new0(SteamUser, 1);
    user->buser = bu;

    return user;
}

/**
 * Frees all memory used by a #SteamUser.
 *
 * @param user The #SteamUser.
 **/
void steam_user_free(SteamUser *user)
{
    if (G_UNLIKELY(user == NULL))
        return;

    g_free(user->server);
    g_free(user->game);
    g_free(user);
}

/**
 * Sends a message to all channels which a #SteamUser is occupying with
 * the sender being the #SteamUser.
 *
 * @param user   The #SteamUser.
 * @param format The format string.
 * @param ...    The arguments for the format string.
 **/
void steam_user_chans_msg(SteamUser *user, const gchar *format, ...)
{
    irc_channel_t *ic;
    irc_user_t    *iu;
    va_list        ap;
    gchar         *str;
    GSList        *l;

    g_return_if_fail(user   != NULL);
    g_return_if_fail(format != NULL);

    va_start(ap, format);
    str = g_strdup_vprintf(format, ap);
    va_end(ap);

    iu = user->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic = l->data;

        if (irc_channel_has_user(ic, iu) != NULL)
            irc_send_msg(iu, "PRIVMSG", ic->name, str, NULL);
    }

    g_free(str);
}

/**
 * Gets the string representation of #SteamUserFlags. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * @param flags The #SteamUserFlags.
 *
 * @return The string representation of the #SteamUserFlags.
 **/
gchar *steam_user_flags_str(SteamUserFlags flags)
{
    gchar **strs;
    gchar  *str;

    static const SteamUtilEnum enums[] = {
        {STEAM_USER_FLAG_WEB,    "Web"},
        {STEAM_USER_FLAG_MOBILE, "Mobile"},
        {STEAM_USER_FLAG_BIGPIC, "Big Picture"},
        STEAM_UTIL_ENUM_NULL
    };

    strs = (gchar **) steam_util_enum_ptrs(enums, flags);

    if (strs[0] == NULL) {
        g_free(strs);
        return NULL;
    }

    str = g_strjoinv(", ", strs);

    g_free(strs);
    return str;
}

/**
 * Creates a new #SteamUserInfo. The returned #SteamUserInfo should be
 * freed with #steam_user_info_free() when no longer needed.
 *
 * @param id The #SteamId.
 *
 * @return The #SteamUserInfo or NULL on error.
 **/
SteamUserInfo *steam_user_info_new(SteamId id)
{
    SteamUserInfo *info;

    info = g_new0(SteamUserInfo, 1);
    info->id  = id;
    info->act = STEAM_USER_ACT_NONE;

    return info;
}

/**
 * Frees all memory used by a #SteamUserInfo.
 *
 * @param info The #SteamUserInfo.
 **/
void steam_user_info_free(SteamUserInfo *info)
{
    if (G_UNLIKELY(info == NULL))
        return;

    g_slist_free_full(info->nicks, g_free);

    g_free(info->profile);
    g_free(info->server);
    g_free(info->game);
    g_free(info->fullname);
    g_free(info->nick);
    g_free(info);
}

/**
 * Creates a new #SteamUserMsg. The returned #SteamUserMsg should be
 * freed with #steam_user_msg_free() when no longer needed.
 *
 * @param id The #SteamId.
 *
 * @return The #SteamUserMsg or NULL on error.
 **/
SteamUserMsg *steam_user_msg_new(SteamId id)
{
    SteamUserMsg *msg;

    msg = g_new0(SteamUserMsg, 1);
    msg->info = steam_user_info_new(id);

    return msg;
}

/**
 * Frees all memory used by a #SteamUserMsg.
 *
 * @param msg The #SteamUserMsg.
 **/
void steam_user_msg_free(SteamUserMsg *msg)
{
    if (G_UNLIKELY(msg == NULL))
        return;

    steam_user_info_free(msg->info);

    g_free(msg->text);
    g_free(msg);
}

/**
 * Gets the string representation of a #SteamUserMsgType.
 *
 * @param type The #SteamUserMsgType.
 *
 * @return The string representation of the #SteamUserMsgType.
 **/
const gchar *steam_user_msg_type_str(SteamUserMsgType type)
{
    static const SteamUtilEnum enums[] = {
        {STEAM_USER_MSG_TYPE_SAYTEXT,      "saytext"},
        {STEAM_USER_MSG_TYPE_EMOTE,        "emote"},
        {STEAM_USER_MSG_TYPE_LEFT_CONV,    "leftconversation"},
        {STEAM_USER_MSG_TYPE_RELATIONSHIP, "personarelationship"},
        {STEAM_USER_MSG_TYPE_STATE,        "personastate"},
        {STEAM_USER_MSG_TYPE_TYPING,       "typing"},
        {STEAM_USER_MSG_TYPE_MY_SAYTEXT,   "my_saytext"},
        {STEAM_USER_MSG_TYPE_MY_EMOTE,     "my_emote"},
        STEAM_UTIL_ENUM_NULL
    };

    return steam_util_enum_ptr(enums, NULL, type);
}

/**
 * Gets the #SteamUserMsgType value of a string.
 *
 * @param type The string.
 *
 * @return The #SteamUserMsgType value.
 **/
SteamUserMsgType steam_user_msg_type_from_str(const gchar *type)
{
    static const SteamUtilEnum enums[] = {
        {STEAM_USER_MSG_TYPE_SAYTEXT,      "saytext"},
        {STEAM_USER_MSG_TYPE_EMOTE,        "emote"},
        {STEAM_USER_MSG_TYPE_LEFT_CONV,    "leftconversation"},
        {STEAM_USER_MSG_TYPE_RELATIONSHIP, "personarelationship"},
        {STEAM_USER_MSG_TYPE_STATE,        "personastate"},
        {STEAM_USER_MSG_TYPE_TYPING,       "typing"},
        {STEAM_USER_MSG_TYPE_MY_SAYTEXT,   "my_saytext"},
        {STEAM_USER_MSG_TYPE_MY_EMOTE,     "my_emote"},
        STEAM_UTIL_ENUM_NULL
    };

    return steam_util_enum_val(enums, STEAM_USER_MSG_TYPE_UNKNOWN, type,
                               (GCompareFunc) g_ascii_strcasecmp);
}

/**
 * Gets the string representation of a #SteamUserState.
 *
 * @param state The #SteamUserState.
 *
 * @return The string representation or NULL on error.
 **/
const gchar *steam_user_state_str(SteamUserState state)
{
    static const SteamUtilEnum enums[] = {
        {STEAM_USER_STATE_OFFLINE, "Offline"},
        {STEAM_USER_STATE_ONLINE,  "Online"},
        {STEAM_USER_STATE_BUSY,    "Busy"},
        {STEAM_USER_STATE_AWAY,    "Away"},
        {STEAM_USER_STATE_SNOOZE,  "Snooze"},
        {STEAM_USER_STATE_TRADE,   "Looking to Trade"},
        {STEAM_USER_STATE_PLAY,    "Looking to Play"},
        STEAM_UTIL_ENUM_NULL
    };

    return steam_util_enum_ptr(enums, NULL, state);
}
