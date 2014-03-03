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

typedef enum   _SteamFriendAction   SteamFriendAction;
typedef enum   _SteamFriendRelation SteamFriendRelation;
typedef enum   _SteamFriendState    SteamFriendState;
typedef struct _SteamFriend         SteamFriend;
typedef struct _SteamFriendSummary  SteamFriendSummary;

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

struct _SteamFriendSummary
{
    SteamFriendState    state;
    SteamFriendRelation relation;
    SteamFriendAction   action;

    gchar *steamid;
    gchar *nick;
    gchar *fullname;
    gchar *game;
    gchar *server;

    gint64 lmesg;
    gint64 lview;
};


SteamFriend *steam_friend_new(bee_user_t *bu);

void steam_friend_free(SteamFriend *frnd);

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...);

void steam_friend_chans_umode(SteamFriend *frnd, gint mode);

SteamFriendSummary *steam_friend_summary_new(const gchar *steamid);

void steam_friend_summary_free(SteamFriendSummary *smry);

const gchar *steam_friend_state_str(SteamFriendState state);

SteamFriendState steam_friend_state_from_str(const gchar *state);

gint steam_friend_user_mode(gchar *mode);

#endif /* _STEAM_FRIEND_H */
