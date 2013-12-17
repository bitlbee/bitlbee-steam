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

#define STEAM_API_HOST          "api.steampowered.com"
#define STEAM_COM_HOST          "steamcommunity.com"
#define STEAM_API_AGENT         "Steam App / " PACKAGE " / " PACKAGE_VERSION
#define STEAM_API_CLIENT_ID     "DE45CD61" /* Public mobile client id */
#define STEAM_API_KEEP_ALIVE    "30"       /* Max of 30 seconds */
#define STEAM_API_STEAMID_START 76561197960265728

#define STEAM_API_PATH_FRIEND_SEARCH "/ISteamUserOAuth/Search/v0001"
#define STEAM_API_PATH_FRIENDS       "/ISteamUserOAuth/GetFriendList/v0001"
#define STEAM_API_PATH_LOGON         "/ISteamWebUserPresenceOAuth/Logon/v0001"
#define STEAM_API_PATH_LOGOFF        "/ISteamWebUserPresenceOAuth/Logoff/v0001"
#define STEAM_API_PATH_MESSAGE       "/ISteamWebUserPresenceOAuth/Message/v0001"
#define STEAM_API_PATH_POLL          "/ISteamWebUserPresenceOAuth/Poll/v0001"
#define STEAM_API_PATH_SUMMARIES     "/ISteamUserOAuth/GetUserSummaries/v0001"

#define STEAM_COM_PATH_AUTH          "/mobilelogin/dologin/"
#define STEAM_COM_PATH_AUTH_RDIR     "/mobileloginsucceeded/"
#define STEAM_COM_PATH_CAPTCHA       "/public/captcha.php"
#define STEAM_COM_PATH_CHATLOG       "/chat/chatlog/"
#define STEAM_COM_PATH_FRIEND_ADD    "/actions/AddFriendAjax/"
#define STEAM_COM_PATH_FRIEND_BLOCK  "/actions/BlockUserAjax/"
#define STEAM_COM_PATH_FRIEND_REMOVE "/actions/RemoveFriendAjax/"
#define STEAM_COM_PATH_KEY           "/mobilelogin/getrsakey/"
#define STEAM_COM_PATH_PROFILE       "/profiles/"

typedef enum   _SteamApiError       SteamApiError;
typedef enum   _SteamApiFlags       SteamApiFlags;
typedef enum   _SteamApiMessageType SteamApiMessageType;
typedef enum   _SteamApiType        SteamApiType;
typedef struct _SteamApi            SteamApi;
typedef struct _SteamApiData        SteamApiData;
typedef struct _SteamApiMessage     SteamApiMessage;

typedef void (*SteamApiFunc)        (SteamApi *api, GError *err,gpointer data);
typedef void (*SteamApiIdFunc)      (SteamApi *api, gchar *steamid,
                                     GError *err, gpointer data);
typedef void (*SteamApiListFunc)    (SteamApi *api, GSList *list, GError *err,
                                     gpointer data);
typedef void (*SteamApiSummaryFunc) (SteamApi *api, SteamFriendSummary *smry,
                                     GError *err, gpointer data);

enum _SteamApiError
{
    STEAM_API_ERROR_AUTH = 0,
    STEAM_API_ERROR_FRIEND_ACCEPT,
    STEAM_API_ERROR_FRIEND_ADD,
    STEAM_API_ERROR_FRIEND_IGNORE,
    STEAM_API_ERROR_FRIEND_REMOVE,
    STEAM_API_ERROR_FRIEND_SEARCH,
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

enum _SteamApiFlags
{
    STEAM_API_FLAG_NOCALL = 1 << 0,
    STEAM_API_FLAG_NOFREE = 1 << 1,
    STEAM_API_FLAG_NOJSON = 1 << 2
};

enum _SteamApiMessageType
{
    STEAM_API_MESSAGE_TYPE_SAYTEXT = 0,
    STEAM_API_MESSAGE_TYPE_EMOTE,
    STEAM_API_MESSAGE_TYPE_LEFT_CONV,
    STEAM_API_MESSAGE_TYPE_RELATIONSHIP,
    STEAM_API_MESSAGE_TYPE_STATE,
    STEAM_API_MESSAGE_TYPE_TYPING,

    STEAM_API_MESSAGE_TYPE_LAST
};

enum _SteamApiType
{
    STEAM_API_TYPE_AUTH = 0,
    STEAM_API_TYPE_AUTH_RDIR,
    STEAM_API_TYPE_CHATLOG,
    STEAM_API_TYPE_FRIEND_ACCEPT,
    STEAM_API_TYPE_FRIEND_ADD,
    STEAM_API_TYPE_FRIEND_IGNORE,
    STEAM_API_TYPE_FRIEND_REMOVE,
    STEAM_API_TYPE_FRIEND_SEARCH,
    STEAM_API_TYPE_FRIENDS,
    STEAM_API_TYPE_KEY,
    STEAM_API_TYPE_LOGOFF,
    STEAM_API_TYPE_LOGON,
    STEAM_API_TYPE_RELOGON,
    STEAM_API_TYPE_MESSAGE,
    STEAM_API_TYPE_POLL,
    STEAM_API_TYPE_SUMMARY,

    STEAM_API_TYPE_LAST
};

struct _SteamApi
{
    gchar  *steamid;
    gchar  *umqid;
    gchar  *token;
    gchar  *sessid;

    gint64 accid;
    gint64 lmid;
    gint64 tstamp;

    SteamHttp *http;
    SteamAuth *auth;
};

struct _SteamApiData
{
    SteamApi      *api;
    SteamApiFlags  flags;
    SteamApiType   type;
    GError        *err;

    gpointer func;
    gpointer data;

    gpointer       rdata;
    GDestroyNotify rfunc;

    GList        *sums;
    SteamHttpReq *req;
};

struct _SteamApiMessage
{
    SteamApiMessageType  type;
    SteamFriendSummary  *smry;

    gchar  *text;
    gint64  tstamp;
};

#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamApi *steam_api_new(const gchar *umqid);

void steam_api_free(SteamApi *api);

gint64 steam_api_accountid(const gchar *steamid);

gchar *steam_api_steamid(gint64 accid);

gchar *steam_api_profile_url(const gchar *steamid);

void steam_api_refresh(SteamApi *api);

const gchar *steam_api_type_str(SteamApiType type);

SteamApiData *steam_api_data_new(SteamApi *api, SteamApiType type,
                                 gpointer func, gpointer data);

void steam_api_data_free(SteamApiData *data);

void steam_api_data_func(SteamApiData *data);

SteamApiMessage *steam_api_message_new(const gchar *steamid);

void steam_api_message_free(SteamApiMessage *mesg);

const gchar *steam_api_message_type_str(SteamApiMessageType type);

SteamApiMessageType steam_api_message_type_from_str(const gchar *type);

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data);

void steam_api_chatlog(SteamApi *api, const gchar *steamid,
                       SteamApiListFunc func, gpointer data);

void steam_api_friend_accept(SteamApi *api, const gchar *steamid,
                             const gchar *action, SteamApiIdFunc func,
                             gpointer data);

void steam_api_friend_add(SteamApi *api, const gchar *steamid,
                          SteamApiIdFunc func, gpointer data);

void steam_api_friend_ignore(SteamApi *api, const gchar *steamid,
                             gboolean ignore, SteamApiIdFunc func,
                             gpointer data);

void steam_api_friend_remove(SteamApi *api, const gchar *steamid,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_search(SteamApi *api, const gchar *search, guint count,
                             SteamApiListFunc func, gpointer data);

void steam_api_friends(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_key(SteamApi *api, const gchar *user, SteamApiFunc func,
                   gpointer data);

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_relogon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_message(SteamApi *api, const SteamApiMessage *mesg,
                       SteamApiFunc func, gpointer data);

void steam_api_poll(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_summary(SteamApi *api, const gchar *steamid,
                       SteamApiSummaryFunc func, gpointer data);

#endif /* _STEAM_API_H */
