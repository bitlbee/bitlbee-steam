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

/** The structure for interacting with the Steam API. **/
typedef struct _SteamApi SteamApi;

/** The structure for #SteamAPI requests. **/
typedef struct _SteamApiReq SteamApiReq;


/**
 * The type of callback for #SteamApiReq operations.
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data or NULL. 
 **/
typedef void (*SteamApiFunc) (SteamApiReq *req, gpointer data);

/**
 * The type of callback for parser based #SteamApiReq operations.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL or NULL.
 **/
typedef void (*SteamApiParser) (SteamApiReq *req, const json_value *json);


/**
 * The #GError codes of #SteamApi.
 **/
enum _SteamApiError
{
    STEAM_API_ERROR_CAPTCHA,    /** Captcha **/
    STEAM_API_ERROR_EXPRIED,    /** Expired session **/
    STEAM_API_ERROR_GENERAL,    /** General **/
    STEAM_API_ERROR_PARSER,     /** JSON parser **/
    STEAM_API_ERROR_STEAMGUARD, /** Steam Guard **/
    STEAM_API_ERROR_UNKNOWN     /** Unknown **/
};

/**
 * The flags of #SteamApiReq.
 **/
enum _SteamApiReqFlags
{
    STEAM_API_REQ_FLAG_NOJSON = 1 << 0 /** Skip JSON parsing **/
};

/**
 * The structure for interacting with the Steam API.
 **/
struct _SteamApi
{
    SteamUserId *id;   /** The #SteamFriendId of the user. **/
    SteamHttp   *http; /** The #SteamHttp for API requests. **/
    GQueue      *msgs; /** The #GQueue of message based #SteamApiReq. **/

    gboolean online;   /** The online state of the user. **/

    gchar *umqid;      /** The unique device identifier. **/
    gchar *token;      /** The session token (mobile requests). **/
    gchar *sessid;     /** The session identifier (community requests). **/

    gint64 lmid;       /** The last message identifier. **/
    gint64 time;       /** The logon timestamp (UTC). **/

    gchar *cgid;       /** The captcha GID (authentication). **/
    gchar *esid;       /** The email SteamID (authentication). **/
    gchar *pkmod;      /** The PKCS (RSA) modulus (authentication). **/
    gchar *pkexp;      /** The PKCS (RSA) exponent (authentication). **/
    gchar *pktime;     /** The PKCS (RSA) key time (authentication). **/
};

/**
 * The structure for #SteamAPI requests.
 **/
struct _SteamApiReq
{
    SteamApi         *api;   /** The #SteamAPI. **/
    SteamApiReqFlags  flags; /** The #SteamApiReqFlags. **/
    SteamHttpReq     *req;   /** The #SteamHttpReq. **/
    GError           *err;   /** The #GError or NULL. **/
    GQueue           *msgs;  /** The #GQueue of #SteamApiMsg. **/ 
    GQueue           *infs;  /** The #GQueue of #SteamUserInfo. **/
    GQueue           *infr;  /** The #GQueue of #SteamUserInfo remaining. **/

    SteamApiFunc      func;  /** The #SteamApiFunc or NULL. **/
    gpointer          data;  /** The user define data or NULL. **/

    SteamApiParser    punc;  /** The #SteamApiParser or NULL. **/
};


#define STEAM_API_ERROR steam_api_error_quark()

GQuark steam_api_error_quark(void);

SteamApi *steam_api_new(const gchar *umqid);

void steam_api_free_auth(SteamApi *api);

void steam_api_free(SteamApi *api);

gchar *steam_api_captcha_url(const gchar *cgid);

gchar *steam_api_profile_url(const SteamUserId *id);

void steam_api_refresh(SteamApi *api);

SteamApiReq *steam_api_req_new(SteamApi *api, SteamApiFunc func, gpointer data);

SteamApiReq *steam_api_req_fwd(SteamApiReq *req);

void steam_api_req_free(SteamApiReq *req);

void steam_api_req_init(SteamApiReq *req, const gchar *host, const gchar *path);

void steam_api_req_auth(SteamApiReq *req, const gchar *user, const gchar *pass,
                        const gchar *authcode, const gchar *captcha);

void steam_api_req_auth_rdir(SteamApiReq *req, GHashTable *params);

void steam_api_req_friends(SteamApiReq *req);

void steam_api_req_key(SteamApiReq *req, const gchar *user);

void steam_api_req_logoff(SteamApiReq *req);

void steam_api_req_logon(SteamApiReq *req);

void steam_api_req_msg(SteamApiReq *req, const SteamUserMsg *msg);

void steam_api_req_poll(SteamApiReq *req);

void steam_api_req_user_accept(SteamApiReq *req, const SteamUserId *id,
                               const gchar *action);

void steam_api_req_user_add(SteamApiReq *req, const SteamUserId *id);

void steam_api_req_user_chatlog(SteamApiReq *req, const SteamUserId *id);

void steam_api_req_user_ignore(SteamApiReq *req, const SteamUserId *id,
                               gboolean ignore);

void steam_api_req_user_info(SteamApiReq *req);

void steam_api_req_user_info_extra(SteamApiReq *req);

void steam_api_req_user_remove(SteamApiReq *req, const SteamUserId *id);

void steam_api_req_user_search(SteamApiReq *req, const gchar *name,
                               guint count);

#endif /* _STEAM_API_H */
