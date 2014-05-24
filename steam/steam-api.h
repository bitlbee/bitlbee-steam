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

/** @file **/

#ifndef _STEAM_API_H
#define _STEAM_API_H

#include <glib.h>

#include "steam-auth.h"
#include "steam-http.h"
#include "steam-json.h"
#include "steam-user.h"


#define STEAM_API_HOST     "api.steampowered.com"
#define STEAM_COM_HOST     "steamcommunity.com"
#define STEAM_API_AGENT    "Steam App / " PACKAGE " / " PACKAGE_VERSION
#define STEAM_API_CLIENTID "DE45CD61"
#define STEAM_API_TIMEOUT  30

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
#define STEAM_COM_PATH_CHAT          "/chat/"
#define STEAM_COM_PATH_CHATLOG       "/chat/chatlog/"
#define STEAM_COM_PATH_FRIEND_ADD    "/actions/AddFriendAjax/"
#define STEAM_COM_PATH_FRIEND_BLOCK  "/actions/BlockUserAjax/"
#define STEAM_COM_PATH_FRIEND_REMOVE "/actions/RemoveFriendAjax/"
#define STEAM_COM_PATH_KEY           "/mobilelogin/getrsakey/"
#define STEAM_COM_PATH_PROFILE       "/profiles/"


/** The #GError codes of #SteamApi. **/
typedef enum _SteamApiError SteamApiError;

/** The flags of #SteamApiReq. **/
typedef enum _SteamApiReqFlags SteamApiReqFlags;

/** The type of #SteamApiReq. **/
typedef enum _SteamApiReqType SteamApiReqType;

/** The structure for interacting with the Steam API. **/
typedef struct _SteamApi SteamApi;

/** The structure for #SteamAPI requests. **/
typedef struct _SteamApiReq SteamApiReq;


/**
 * The type of callback for generic #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiFunc) (SteamApi *api, const GError *err, gpointer data);

/**
 * The type of callback for #SteamUserId based #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiIdFunc) (SteamApi *api, const SteamUserId *id,
                                const GError *err, gpointer data);

/**
 * The type of callback for #GSList based #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param list The #GSList of items.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiListFunc) (SteamApi *api, const GSList *list,
                                  const GError *err, gpointer data);

/**
 * The type of callback for parser based #SteamApiReq operations.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL or NULL.
 **/
typedef void (*SteamApiParseFunc) (SteamApiReq *req, const json_value *json);

/**
 * The type of callback for #SteamUserInfo based #SteamApi
 * operations.
 *
 * @param api  The #SteamApi.
 * @param info The #SteamUserInfo.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiInfoFunc) (SteamApi *api, const SteamUserInfo *info,
                                  const GError *err, gpointer data);


/**
 * The #GError codes of #SteamApi.
 **/
enum _SteamApiError
{
    STEAM_API_ERROR_AUTH = 0,      /** Authentication **/
    STEAM_API_ERROR_FRIEND_ACCEPT, /** Friend accept **/
    STEAM_API_ERROR_FRIEND_ADD,    /** Friend add **/
    STEAM_API_ERROR_FRIEND_IGNORE, /** Friend ignore **/
    STEAM_API_ERROR_FRIEND_REMOVE, /** Friend remove **/
    STEAM_API_ERROR_FRIEND_SEARCH, /** Friend search **/
    STEAM_API_ERROR_FRIENDS,       /** Friends list **/
    STEAM_API_ERROR_FRIENDS_CINFO, /** Friends chat info **/
    STEAM_API_ERROR_KEY,           /** PKCS Key **/
    STEAM_API_ERROR_LOGOFF,        /** Logoff **/
    STEAM_API_ERROR_LOGON,         /** Logon **/
    STEAM_API_ERROR_RELOGON,       /** Relogon **/
    STEAM_API_ERROR_MESSAGE,       /** Message **/
    STEAM_API_ERROR_POLL,          /** Poll **/
    STEAM_API_ERROR_SUMMARIES,     /** Summaries **/
    STEAM_API_ERROR_SUMMARY,       /** Summary **/

    STEAM_API_ERROR_AUTH_CAPTCHA,  /** Captcha **/
    STEAM_API_ERROR_AUTH_GUARD,    /** Steam Guard **/
    STEAM_API_ERROR_EMPTY_REPLY,   /** Empty reply **/
    STEAM_API_ERROR_PARSER         /** JSON parser **/
};

/**
 * The flags of #SteamApiReq.
 **/
enum _SteamApiReqFlags
{
    STEAM_API_REQ_FLAG_NOCALL = 1 << 0, /** Skip calling back **/
    STEAM_API_REQ_FLAG_NOFREE = 1 << 1, /** Skip freeing the #SteamApiReq **/
    STEAM_API_REQ_FLAG_NOJSON = 1 << 2  /** Skip JSON parsing **/
};

/**
 * The type of #SteamApiReq.
 **/
enum _SteamApiReqType
{
    STEAM_API_REQ_TYPE_NONE = 0,      /** None (default) **/

    STEAM_API_REQ_TYPE_AUTH,          /** Authentication **/
    STEAM_API_REQ_TYPE_AUTH_RDIR,     /** Authentication redirect **/
    STEAM_API_REQ_TYPE_CHATLOG,       /** Chatlog **/
    STEAM_API_REQ_TYPE_FRIEND_ACCEPT, /** Friend accept **/
    STEAM_API_REQ_TYPE_FRIEND_ADD,    /** Friend add **/
    STEAM_API_REQ_TYPE_FRIEND_IGNORE, /** Friend ignore **/
    STEAM_API_REQ_TYPE_FRIEND_REMOVE, /** Friend remove **/
    STEAM_API_REQ_TYPE_FRIEND_SEARCH, /** Friend search **/
    STEAM_API_REQ_TYPE_FRIENDS,       /** Friends list **/
    STEAM_API_REQ_TYPE_FRIENDS_CINFO, /** Friends chat info **/
    STEAM_API_REQ_TYPE_KEY,           /** PKCS key **/
    STEAM_API_REQ_TYPE_LOGOFF,        /** Logoff **/
    STEAM_API_REQ_TYPE_LOGON,         /** Logon **/
    STEAM_API_REQ_TYPE_RELOGON,       /** Relogon **/
    STEAM_API_REQ_TYPE_MESSAGE,       /** Message **/
    STEAM_API_REQ_TYPE_POLL,          /** Poll **/
    STEAM_API_REQ_TYPE_SUMMARIES,     /** Summaries **/
    STEAM_API_REQ_TYPE_SUMMARY,       /** Summary **/

    STEAM_API_REQ_TYPE_LAST           /** Last **/
};

/**
 * The structure for interacting with the Steam API.
 **/
struct _SteamApi
{
    SteamUserId *id; /** The #SteamUserId of the user. **/

    gchar *umqid;    /** The unique device identifier. **/
    gchar *token;    /** The session token (mobile requests). **/
    gchar *sessid;   /** The session identifier (community requests). **/

    gint64 lmid;     /** The last message identifier. **/
    gint64 time;     /** The logon timestamp (UTC). **/

    SteamHttp *http; /** The #SteamHttp for API requests. **/
    SteamAuth *auth; /** The #SteamAuth for authorization requests. **/
};

/**
 * The structure for #SteamAPI requests.
 **/
struct _SteamApiReq
{
    SteamApiReqType  type;  /** The #SteamApiReqType. **/
    SteamApiReqFlags flags; /** The #SteamApiReqFlags. **/

    SteamApi     *api;      /** The #SteamAPI. **/
    SteamHttpReq *req;      /** The #SteamHttpReq. **/
    GError       *err;      /** The #GError or NULL. **/
    GList        *infos;    /** The #GList of #SteamUserInfo. **/

    gpointer func;          /** The user callback function or NULL. **/
    gpointer data;          /** The user define data or NULL **/

    gpointer       rdata;   /** The return data or NULL. **/
    GDestroyNotify rfunc;   /** The free function for #rdata or NULL. **/

    SteamApiReqType typel;  /** The last #SteamApiReqType. **/
};


#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamApi *steam_api_new(const gchar *umqid);

void steam_api_free(SteamApi *api);

gchar *steam_api_profile_url(const SteamUserId *id);

void steam_api_refresh(SteamApi *api);

SteamApiReq *steam_api_req_new(SteamApi *api, SteamApiReqType type,
                               gpointer func, gpointer data);

void steam_api_req_free(SteamApiReq *req);

void steam_api_req_func(SteamApiReq *req);

const gchar *steam_api_req_type_str(SteamApiReqType type);

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data);

void steam_api_chatlog(SteamApi *api, const SteamUserId *id,
                       SteamApiListFunc func, gpointer data);

void steam_api_friend_accept(SteamApi *api, const SteamUserId *id,
                             const gchar *action,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_add(SteamApi *api, const SteamUserId *id,
                          SteamApiIdFunc func, gpointer data);

void steam_api_friend_ignore(SteamApi *api, const SteamUserId *id,
                             gboolean ignore,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_remove(SteamApi *api, const SteamUserId *id,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_search(SteamApi *api, const gchar *search, guint count,
                             SteamApiListFunc func, gpointer data);

void steam_api_friends(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_key(SteamApi *api, const gchar *user,
                   SteamApiFunc func, gpointer data);

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_message(SteamApi *api, const SteamUserMsg *msg,
                       SteamApiFunc func, gpointer data);

void steam_api_poll(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_summary(SteamApi *api, const SteamUserId *id,
                       SteamApiInfoFunc func, gpointer data);

#endif /* _STEAM_API_H */
