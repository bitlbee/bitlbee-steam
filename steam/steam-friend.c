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

#include <string.h>

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
    if (G_UNLIKELY(frnd == NULL))
        return;

    g_free(frnd->server);
    g_free(frnd->game);
    g_free(frnd);
}

SteamFriendId *steam_friend_id_new(gint64 id)
{
    SteamFriendId *fnid;

    fnid = g_new0(SteamFriendId, 1);

    fnid->steam.i  = id;
    fnid->steam.s  = g_strdup_printf("%" G_GINT64_FORMAT, fnid->steam.i);

    fnid->commu.i  = STEAM_FRIEND_ID_NUMBER(id);
    fnid->commu.s  = g_strdup_printf("%" G_GINT64_FORMAT, fnid->commu.i);

    fnid->type     = STEAM_FRIEND_ID_TYPE(fnid->steam.i);
    fnid->universe = STEAM_FRIEND_ID_UNIVERSE(fnid->steam.i);

    return fnid;
}

SteamFriendId *steam_friend_id_new_str(const gchar *id)
{
    gint64 in;

    g_return_val_if_fail(id != NULL, NULL);

    in = g_ascii_strtoll(id, NULL, 10);
    return steam_friend_id_new(in);
}

SteamFriendId *steam_friend_id_dup(SteamFriendId *id)
{
    SteamFriendId *fnid;

    g_return_val_if_fail(id != NULL, NULL);

    fnid = g_memdup(id, sizeof *id);
    fnid->steam.s = g_strdup(fnid->steam.s);
    fnid->commu.s = g_strdup(fnid->commu.s);

    return fnid;
}

void steam_friend_id_free(SteamFriendId *id)
{
    if (G_UNLIKELY(id == NULL))
        return;

    g_free(id->steam.s);
    g_free(id->commu.s);
    g_free(id);
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

void steam_friend_chans_umode(SteamFriend *frnd, gint mode, gboolean override)
{
    irc_channel_t            *ic;
    irc_user_t               *iu;
    irc_channel_user_t       *icu;
    irc_channel_user_flags_t  flags;
    irc_channel_user_flags_t  flag;
    GSList                   *l;
    guint                     i;

    g_return_if_fail(frnd != NULL);

    iu = frnd->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic  = l->data;
        icu = irc_channel_has_user(ic, iu);

        if (icu == NULL)
            continue;

        if (override) {
            for (flags = mode, i = 3; i >= 0; i--) {
                flag = 1 << i;

                if (mode & flag)
                    break;

                if (icu->flags & flag)
                    flags |= flag;
            }
        } else {
            flags = icu->flags | mode;
        }

        irc_channel_user_set_mode(ic, iu, flags);
    }
}

SteamFriendSummary *steam_friend_summary_new(gint64 id)
{
    SteamFriendSummary *smry;

    smry = g_new0(SteamFriendSummary, 1);
    smry->id     = steam_friend_id_new(id);
    smry->action = STEAM_FRIEND_ACTION_NONE;

    return smry;
}

SteamFriendSummary *steam_friend_summary_new_str(const gchar *id)
{
    gint64 in;

    g_return_val_if_fail(id != NULL, NULL);

    in = g_ascii_strtoll(id, NULL, 10);
    return steam_friend_summary_new(in);
}

void steam_friend_summary_free(SteamFriendSummary *smry)
{
    if (G_UNLIKELY(smry == NULL))
        return;

    steam_friend_id_free(smry->id);

    g_free(smry->server);
    g_free(smry->game);
    g_free(smry->fullname);
    g_free(smry->nick);
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

    if ((state < 0) || (state >= STEAM_FRIEND_STATE_LAST))
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

gint steam_friend_user_mode(gchar *mode)
{
    if ((mode == NULL) || (strlen(mode) < 1))
        return IRC_CHANNEL_USER_NONE;

    switch (mode[0]) {
    case '@': return IRC_CHANNEL_USER_OP;
    case '%': return IRC_CHANNEL_USER_HALFOP;
    case '+': return IRC_CHANNEL_USER_VOICE;

    default:
        return IRC_CHANNEL_USER_NONE;
    }
}
