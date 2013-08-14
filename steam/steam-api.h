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

#ifndef _STEAM_API_H
#define _STEAM_API_H

#include "steam-auth.h"
#include "steam-friend.h"
#include "steam-http.h"

#define STEAM_API_HOST            "api.steampowered.com"
#define STEAM_COM_HOST            "steamcommunity.com"
#define STEAM_API_AGENT           "Steam App / " PACKAGE " / " \
                                  PACKAGE_VERSION " / 0"

#define STEAM_API_CLIENT_ID       "DE45CD61" /* Public mobile client id */
#define STEAM_API_KEEP_ALIVE      "15"       /* Max of 30 seconds */

#define STEAM_API_PATH_FRIENDS    "/ISteamUserOAuth/GetFriendList/v0001"
#define STEAM_API_PATH_LOGON      "/ISteamWebUserPresenceOAuth/Logon/v0001"
#define STEAM_API_PATH_LOGOFF     "/ISteamWebUserPresenceOAuth/Logoff/v0001"
#define STEAM_API_PATH_MESSAGE    "/ISteamWebUserPresenceOAuth/Message/v0001"
#define STEAM_API_PATH_POLL       "/ISteamWebUserPresenceOAuth/Poll/v0001"
#define STEAM_API_PATH_SUMMARIES  "/ISteamUserOAuth/GetUserSummaries/v0001"

#define STEAM_COM_PATH_AUTH       "/mobilelogin/dologin/"
#define STEAM_COM_PATH_CAPTCHA    "/public/captcha.php"
#define STEAM_COM_PATH_KEY        "/mobilelogin/getrsakey/"

typedef enum   _SteamApiError    SteamApiError;
typedef enum   _SteamState       SteamState;
typedef enum   _SteamMessageType SteamMessageType;
typedef struct _SteamApi         SteamApi;
typedef struct _SteamMessage     SteamMessage;
typedef struct _SteamSummary     SteamSummary;

typedef void (*SteamApiFunc)  (SteamApi *api, GError *err,gpointer data);
typedef void (*SteamListFunc) (SteamApi *api, GSList *list, GError *err,
                               gpointer data);

enum _SteamApiError
{
    STEAM_API_ERROR_AUTH = 0,
    STEAM_API_ERROR_FRIENDS,
    STEAM_API_ERROR_KEY,
    STEAM_API_ERROR_LOGOFF,
    STEAM_API_ERROR_LOGON,
    STEAM_API_ERROR_RELOGON,
    STEAM_API_ERROR_MESSAGE,
    STEAM_API_ERROR_POLL,
    STEAM_API_ERROR_SUMMARIES,

    STEAM_API_ERROR_AUTH_CAPTCHA,
    STEAM_API_ERROR_AUTH_GUARD,
    STEAM_API_ERROR_EMPTY_REPLY,
    STEAM_API_ERROR_LOGON_EXPIRED,
    STEAM_API_ERROR_PARSER
};

enum _SteamState
{
    STEAM_STATE_OFFLINE = 0,
    STEAM_STATE_ONLINE  = 1,
    STEAM_STATE_BUSY    = 2,
    STEAM_STATE_AWAY    = 3,
    STEAM_STATE_SNOOZE  = 4,
    STEAM_STATE_TRADE   = 5,
    STEAM_STATE_PLAY    = 6,

    STEAM_STATE_LAST
};

enum _SteamMessageType
{
    STEAM_MESSAGE_TYPE_SAYTEXT = 0,
    STEAM_MESSAGE_TYPE_EMOTE,
    STEAM_MESSAGE_TYPE_LEFT_CONV,
    STEAM_MESSAGE_TYPE_RELATIONSHIP,
    STEAM_MESSAGE_TYPE_STATE,
    STEAM_MESSAGE_TYPE_TYPING,

    STEAM_MESSAGE_TYPE_LAST
};

struct _SteamApi
{
    gchar  *steamid;
    gchar  *umqid;
    gchar  *token;
    gint64  lmid;

    SteamHttp *http;
    SteamAuth *auth;
};

struct _SteamMessage
{
    SteamMessageType type;
    SteamState       state;
    SteamFriendState fstate;

    gchar *steamid;
    gchar *text;
    gchar *nick;
};

struct _SteamSummary
{
    SteamState state;

    gchar *steamid;
    gchar *nick;
    gchar *fullname;
    gchar *profile;
    gchar *game;
    gchar *server;
};

#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamApi *steam_api_new(const gchar *umqid);

void steam_api_free(SteamApi *api);

SteamMessage *steam_message_new(const gchar *steamid);

void steam_message_free(SteamMessage *sm);

SteamSummary *steam_summary_new(const gchar *steamid);

void steam_summary_free(SteamSummary *ss);

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data);

void steam_api_friends(SteamApi *api, SteamListFunc func, gpointer data);

void steam_api_key(SteamApi *api, const gchar *user, SteamApiFunc func,
                   gpointer data);

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_relogon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_message(SteamApi *api, SteamMessage *sm, SteamApiFunc func,
                       gpointer data);

void steam_api_poll(SteamApi *api, SteamListFunc func, gpointer data);

void steam_api_summaries(SteamApi *api, GSList *friends, SteamListFunc func,
                         gpointer data);

void steam_api_summary(SteamApi *api, const gchar *steamid, SteamListFunc func,
                       gpointer data);

const gchar *steam_message_type_str(SteamMessageType type);

const gchar *steam_state_str(SteamState state);

SteamState steam_state_from_str(const gchar *state);

#endif /* _STEAM_API_H */
