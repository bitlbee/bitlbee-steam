/*
 * Copyright 2012 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_API_H
#define _STEAM_API_H

#include "steam-http.h"

#define STEAM_API_HOST        "api.steampowered.com"
#define STEAM_API_AGENT       "Steam App / BitlBee / " PACKAGE_VERSION " / 0"
#define STEAM_API_KEEP_ALIVE  "30" /* Max of 30 seconds */

/* Required for GetTokenWithCredentials */
#define STEAM_API_AGENT_AUTH  "Steam App / Android / 1.0 / 0"
#define STEAM_API_CLIENT_ID   "DE45CD61" /* The "public" mobile client id */

#define STEAM_PATH_AUTH       "/ISteamOAuth2/GetTokenWithCredentials/v0001"
#define STEAM_PATH_FRIENDS    "/ISteamUserOAuth/GetFriendList/v0001"
#define STEAM_PATH_LOGON      "/ISteamWebUserPresenceOAuth/Logon/v0001"
#define STEAM_PATH_LOGOFF     "/ISteamWebUserPresenceOAuth/Logoff/v0001"
#define STEAM_PATH_MESSAGE    "/ISteamWebUserPresenceOAuth/Message/v0001"
#define STEAM_PATH_POLL       "/ISteamWebUserPresenceOAuth/Poll/v0001"
#define STEAM_PATH_SUMMARIES  "/ISteamUserOAuth/GetUserSummaries/v0001"

typedef enum   _SteamApiError    SteamApiError;
typedef enum   _SteamState       SteamState;
typedef enum   _SteamMessageType SteamMessageType;
typedef struct _SteamAPI         SteamAPI;
typedef struct _SteamMessage     SteamMessage;
typedef struct _SteamSummary     SteamSummary;

typedef void (*SteamApiFunc)  (SteamAPI *api, GError *err, gpointer data);

typedef void (*SteamListFunc) (SteamAPI *api, GSList *list, GError *err,
                               gpointer data);

enum _SteamApiError
{
    STEAM_API_ERROR_AUTH = 0,
    STEAM_API_ERROR_FRIENDS,
    STEAM_API_ERROR_LOGOFF,
    STEAM_API_ERROR_LOGON,
    STEAM_API_ERROR_MESSAGE,
    STEAM_API_ERROR_POLL,
    STEAM_API_ERROR_SUMMARIES,

    STEAM_API_ERROR_AUTH_REQ,
    STEAM_API_ERROR_EMPTY_REPLY
};

enum _SteamState
{
    STEAM_STATE_OFFLINE = 0,
    STEAM_STATE_ONLINE  = 1,
    STEAM_STATE_BUSY    = 2,
    STEAM_STATE_AWAY    = 3,
    STEAM_STATE_SNOOZE  = 4,

    STEAM_STATE_LAST
};

enum _SteamMessageType
{
    STEAM_MESSAGE_TYPE_SAYTEXT = 0,
    STEAM_MESSAGE_TYPE_EMOTE,
    STEAM_MESSAGE_TYPE_LEFT_CONV,
    STEAM_MESSAGE_TYPE_STATE,
    STEAM_MESSAGE_TYPE_TYPING,

    STEAM_MESSAGE_TYPE_LAST
};

struct _SteamAPI
{
    gchar *token;
    gchar *steamid;
    gchar *umqid;
    gchar *lmid;

    SteamHttp *http;
};

struct _SteamMessage
{
    SteamMessageType type;
    SteamState       state;

    const gchar *steamid;
    const gchar *text;
    const gchar *nick;
};

struct _SteamSummary
{
    SteamState state;

    const gchar *steamid;
    const gchar *nick;
    const gchar *fullname;
    const gchar *profile;
    const gchar *game;
    const gchar *server;
};

#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamAPI *steam_api_new(const gchar *umqid);

void steam_api_free(SteamAPI *api);

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    const gchar *user, const gchar *pass,
                    SteamApiFunc func, gpointer data);

void steam_api_friends(SteamAPI *api, SteamListFunc func, gpointer data);

void steam_api_logon(SteamAPI *api, SteamApiFunc func, gpointer data);

void steam_api_logoff(SteamAPI *api, SteamApiFunc func, gpointer data);

void steam_api_message(SteamAPI *api, SteamMessage *sm, SteamApiFunc func,
                       gpointer data);

void steam_api_poll(SteamAPI *api, SteamListFunc func, gpointer data);

void steam_api_summaries(SteamAPI *api, GSList *friends, SteamListFunc func,
                        gpointer data);

void steam_api_summary(SteamAPI *api, const gchar *steamid, SteamListFunc func,
                       gpointer data);

gchar *steam_message_type_str(SteamMessageType type);

gchar *steam_state_str(SteamState state);

SteamState steam_state_from_str(const gchar *state);

#endif /* _STEAM_API_H */
