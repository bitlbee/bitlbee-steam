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
#include "steam-friend.h"
#include "steam-http.h"
#include "steam-json.h"


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


/** The #GError codes of #SteamApiData. **/
typedef enum _SteamApiError SteamApiError;

/** The flags of #SteamApiData. **/
typedef enum _SteamApiFlags SteamApiFlags;

/** The type of #SteamApiMessage. **/
typedef enum _SteamApiMessageType SteamApiMessageType;

/** The type of #SteamApiData. **/
typedef enum _SteamApiType SteamApiType;

/** The structure for interacting with the Steam API. **/
typedef struct _SteamApi SteamApi;

/** The structure for #SteamAPI requests. **/
typedef struct _SteamApiData SteamApiData;

/** The structure for #SteamAPI messages. **/
typedef struct _SteamApiMessage SteamApiMessage;


/**
 * The type of callback for generic #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiFunc) (SteamApi *api, GError *err, gpointer data);

/**
 * The type of callback for #SteamFriendId based #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamFriendId.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiIdFunc) (SteamApi *api, SteamFriendId *id, GError *err,
                                gpointer data);

/**
 * The type of callback for #GSList based #SteamApi operations.
 *
 * @param api  The #SteamApi.
 * @param list The #GSList of items.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiListFunc) (SteamApi *api, GSList *list, GError *err,
                                  gpointer data);

/**
 * The type of callback for parser based #SteamApiData operations.
 *
 * @param sata The #SteamApiData.
 * @param json The #json_value or NULL or NULL.
 **/
typedef void (*SteamApiParseFunc) (SteamApiData *sata, json_value *json);

/**
 * The type of callback for #SteamFriendSummary based #SteamApi
 * operations.
 *
 * @param api  The #SteamApi.
 * @param smry The #SteamFriendSummary.
 * @param err  The #GError upon an error, otherwise NULL.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiSummaryFunc) (SteamApi *api, SteamFriendSummary *smry,
                                     GError *err, gpointer data);


/**
 * The #GError codes of #SteamApiData.
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
 * The flags of #SteamApiData.
 **/
enum _SteamApiFlags
{
    STEAM_API_FLAG_NOCALL = 1 << 0, /** Skip calling back **/
    STEAM_API_FLAG_NOFREE = 1 << 1, /** Skip freeing the #SteamApiData **/
    STEAM_API_FLAG_NOJSON = 1 << 2  /** Skip JSON parsing **/
};

/**
 * The type of #SteamApiMessage.
 **/
enum _SteamApiMessageType
{
    STEAM_API_MESSAGE_TYPE_SAYTEXT = 0,  /** Say text (default) **/
    STEAM_API_MESSAGE_TYPE_EMOTE,        /** Emote **/
    STEAM_API_MESSAGE_TYPE_LEFT_CONV,    /** Left conversation **/
    STEAM_API_MESSAGE_TYPE_RELATIONSHIP, /** Relationship **/
    STEAM_API_MESSAGE_TYPE_STATE,        /** State **/
    STEAM_API_MESSAGE_TYPE_TYPING,       /** Typing **/

    STEAM_API_MESSAGE_TYPE_LAST          /** Last **/
};

/**
 * The type of #SteamApiData.
 **/
enum _SteamApiType
{
    STEAM_API_TYPE_NONE = 0,      /** None (default) **/

    STEAM_API_TYPE_AUTH,          /** Authentication **/
    STEAM_API_TYPE_AUTH_RDIR,     /** Authentication redirect **/
    STEAM_API_TYPE_CHATLOG,       /** Chatlog **/
    STEAM_API_TYPE_FRIEND_ACCEPT, /** Friend accept **/
    STEAM_API_TYPE_FRIEND_ADD,    /** Friend add **/
    STEAM_API_TYPE_FRIEND_IGNORE, /** Friend ignore **/
    STEAM_API_TYPE_FRIEND_REMOVE, /** Friend remove **/
    STEAM_API_TYPE_FRIEND_SEARCH, /** Friend search **/
    STEAM_API_TYPE_FRIENDS,       /** Friends list **/
    STEAM_API_TYPE_FRIENDS_CINFO, /** Friends chat info **/
    STEAM_API_TYPE_KEY,           /** PKCS key **/
    STEAM_API_TYPE_LOGOFF,        /** Logoff **/
    STEAM_API_TYPE_LOGON,         /** Logon **/
    STEAM_API_TYPE_RELOGON,       /** Relogon **/
    STEAM_API_TYPE_MESSAGE,       /** Message **/
    STEAM_API_TYPE_POLL,          /** Poll **/
    STEAM_API_TYPE_SUMMARIES,     /** Summaries **/
    STEAM_API_TYPE_SUMMARY,       /** Summary **/

    STEAM_API_TYPE_LAST           /** Last **/
};

/**
 * The structure for interacting with the Steam API.
 **/
struct _SteamApi
{
    SteamFriendId *id; /** The #SteamFriendId of the user. **/

    gchar *umqid;      /** The unique device identifier. **/
    gchar *token;      /** The session token (mobile requests). **/
    gchar *sessid;     /** The session identifier (community requests). **/

    gint64 lmid;       /** The last message identifier. **/
    gint64 tstamp;     /** The logon timestamp (UTC). **/

    SteamHttp *http;   /** The #SteamHttp for API requests. **/
    SteamAuth *auth;   /** The #SteamAuth for authorization requests. **/
};

/**
 * The structure for #SteamAPI requests.
 **/
struct _SteamApiData
{
    SteamApiType  type;   /** The #SteamApiType. **/
    SteamApiFlags flags;  /** The #SteamApiFlags. **/

    SteamApi     *api;    /** The #SteamAPI. **/
    SteamHttpReq *req;    /** The #SteamHttpReq. **/
    GError       *err;    /** The #GError or NULL. **/
    GList        *sums;   /** The #GList of #SteamFriendSummary. **/

    gpointer func;        /** The user callback function or NULL. **/
    gpointer data;        /** The user define data or NULL **/

    gpointer       rdata; /** The return data or NULL. **/
    GDestroyNotify rfunc; /** The free function for #rdata or NULL. **/

    SteamApiType typel;   /** The last #SteamApiType. **/
};

/**
 * The structure for #SteamAPI messages.
 **/
struct _SteamApiMessage
{
    SteamApiMessageType  type; /** The #SteamApiMessageType. **/
    SteamFriendSummary  *smry; /** The #SteamFriendSummary. **/

    gchar  *text;              /** The message text or NULL. **/
    gint64  tstamp;            /** The message timestamp (UTC) or NULL **/
};


#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamApi *steam_api_new(const gchar *umqid);

void steam_api_free(SteamApi *api);

gchar *steam_api_profile_url(SteamFriendId *id);

void steam_api_refresh(SteamApi *api);

const gchar *steam_api_type_str(SteamApiType type);

SteamApiData *steam_api_data_new(SteamApi *api, SteamApiType type,
                                 gpointer func, gpointer data);

void steam_api_data_free(SteamApiData *data);

void steam_api_data_func(SteamApiData *data);

SteamApiMessage *steam_api_message_new(gint64 id);

SteamApiMessage *steam_api_message_new_str(const gchar *id);

void steam_api_message_free(SteamApiMessage *mesg);

const gchar *steam_api_message_type_str(SteamApiMessageType type);

SteamApiMessageType steam_api_message_type_from_str(const gchar *type);

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data);

void steam_api_chatlog(SteamApi *api, SteamFriendId *id,
                       SteamApiListFunc func, gpointer data);

void steam_api_friend_accept(SteamApi *api, SteamFriendId *id,
                             const gchar *action, SteamApiIdFunc func,
                             gpointer data);

void steam_api_friend_add(SteamApi *api, SteamFriendId *id,
                          SteamApiIdFunc func, gpointer data);

void steam_api_friend_ignore(SteamApi *api, SteamFriendId *id, gboolean ignore,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_remove(SteamApi *api, SteamFriendId *id,
                             SteamApiIdFunc func, gpointer data);

void steam_api_friend_search(SteamApi *api, const gchar *search, guint count,
                             SteamApiListFunc func, gpointer data);

void steam_api_friends(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_key(SteamApi *api, const gchar *user,
                   SteamApiFunc func, gpointer data);

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data);

void steam_api_message(SteamApi *api, const SteamApiMessage *mesg,
                       SteamApiFunc func, gpointer data);

void steam_api_poll(SteamApi *api, SteamApiListFunc func, gpointer data);

void steam_api_summary(SteamApi *api, SteamFriendId *id,
                       SteamApiSummaryFunc func, gpointer data);

#endif /* _STEAM_API_H */
