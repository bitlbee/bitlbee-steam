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

#include "steam-friend.h"

SteamFriend *steam_friend_new(bee_user_t *bu)
{
    SteamFriend *frnd;

    frnd = g_new0(SteamFriend, 1);
    frnd->buser = bu;

    return frnd;
}

void steam_friend_free(SteamFriend *frnd)
{
    g_return_if_fail(frnd != NULL);

    g_free(frnd->server);
    g_free(frnd->game);

    g_free(frnd);
}

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...)
{
    irc_channel_t *ic;
    irc_user_t    *iu;
    va_list        ap;
    gchar         *str;
    GSList        *l;

    g_return_if_fail(frnd   != NULL);
    g_return_if_fail(format != NULL);

    va_start(ap, format);
    str = g_strdup_vprintf(format, ap);
    va_end(ap);

    iu = frnd->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic = l->data;

        if (irc_channel_has_user(ic, iu) != NULL)
            irc_send_msg(iu, "PRIVMSG", ic->name, str, NULL);
    }

    g_free(str);
}

void steam_friend_chans_umode(SteamFriend *frnd, gint mode)
{
    irc_channel_t      *ic;
    irc_user_t         *iu;
    irc_channel_user_t *icu;
    GSList             *l;

    g_return_if_fail(frnd   != NULL);

    iu = frnd->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic  = l->data;
        icu = irc_channel_has_user(ic, iu);

        if (icu != NULL)
            irc_channel_user_set_mode(ic, iu, icu->flags | mode);
    }
}

SteamFriendSummary *steam_friend_summary_new(const gchar *steamid)
{
    SteamFriendSummary *smry;

    smry = g_new0(SteamFriendSummary, 1);
    smry->action  = STEAM_FRIEND_ACTION_NONE;
    smry->steamid = g_strdup(steamid);

    return smry;
}

void steam_friend_summary_free(SteamFriendSummary *smry)
{
    g_return_if_fail(smry != NULL);

    g_free(smry->server);
    g_free(smry->game);
    g_free(smry->fullname);
    g_free(smry->nick);
    g_free(smry->steamid);
    g_free(smry);
}

const gchar *steam_friend_state_str(SteamFriendState state)
{
    static const gchar *strs[STEAM_FRIEND_STATE_LAST] = {
        [STEAM_FRIEND_STATE_OFFLINE] = "Offline",
        [STEAM_FRIEND_STATE_ONLINE]  = "Online",
        [STEAM_FRIEND_STATE_BUSY]    = "Busy",
        [STEAM_FRIEND_STATE_AWAY]    = "Away",
        [STEAM_FRIEND_STATE_SNOOZE]  = "Snooze",
        [STEAM_FRIEND_STATE_TRADE]   = "Looking to Trade",
        [STEAM_FRIEND_STATE_PLAY]    = "Looking to Play"
    };

    if ((state < 0) || (state > STEAM_FRIEND_STATE_LAST))
        return "Offline";

    return strs[state];
}

SteamFriendState steam_friend_state_from_str(const gchar *state)
{
    const gchar *s;
    guint        i;

    if (state == NULL)
        return STEAM_FRIEND_STATE_OFFLINE;

    for (i = 0; i < STEAM_FRIEND_STATE_LAST; i++) {
        s = steam_friend_state_str(i);

        if (g_ascii_strcasecmp(state, s) == 0)
            return i;
    }

    return STEAM_FRIEND_STATE_OFFLINE;
}
