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

#ifndef _STEAM_FRIEND_H
#define _STEAM_FRIEND_H

#include <bitlbee.h>

typedef enum   _SteamFriendFlags SteamFriendFlags;
typedef enum   _SteamFriendState SteamFriendState;
typedef struct _SteamFriend      SteamFriend;

enum _SteamFriendFlags
{
    STEAM_FRIEND_FLAG_PENDING = 1 << 0
};

enum _SteamFriendState
{
    STEAM_FRIEND_STATE_REMOVE    = 0,
    STEAM_FRIEND_STATE_IGNORE    = 1,
    STEAM_FRIEND_STATE_REQUEST   = 2,
    STEAM_FRIEND_STATE_ADD       = 3,
    STEAM_FRIEND_STATE_REQUESTED = 4,

    STEAM_FRIEND_STATE_NONE,
    STEAM_FRIEND_STATE_LAST
};

struct _SteamFriend
{
    bee_user_t *buser;

    SteamFriendFlags flags;
    SteamFriendState state;

    gchar *game;
    gchar *server;
};


SteamFriend *steam_friend_new(bee_user_t *bu);

void steam_friend_free(SteamFriend *frnd);

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...);

void steam_friend_chans_umode(SteamFriend *frnd, gint mode);

#endif /* _STEAM_FRIEND_H */
