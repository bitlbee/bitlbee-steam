/*
 * Copyright 2012-2016 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_API_H_
#define _STEAM_API_H_

/**
 * SECTION:api
 * @section_id: steam-api
 * @short_description: <filename>steam-api.h</filename>
 * @title: Steam API
 *
 * The API for interacting with the Steam Web protocol.
 */

#include "steam-glib.h"
#include "steam-http.h"
#include "steam-json.h"
#include "steam-user.h"

/**
 * STEAM_API_HOST:
 *
 * The HTTP host for the Steam API.
 */
#define STEAM_API_HOST  "api.steampowered.com"

/**
 * STEAM_COM_HOST:
 *
 * The HTTP host for the Steam Community.
 */
#define STEAM_COM_HOST  "steamcommunity.com"

/**
 * STEAM_API_AGENT:
 *
 * The HTTP user-agent for the Steam requests.
 */
#define STEAM_API_AGENT  "Steam App / " PACKAGE " / " PACKAGE_VERSION

/**
 * STEAM_API_CLIENT:
 *
 * The Steam client.
 */
#define STEAM_API_CLIENT  "android"

/**
 * STEAM_API_CLIENT_ID:
 *
 * The Steam client identifier.
 */
#define STEAM_API_CLIENT_ID  "DE45CD61"

/**
 * STEAM_API_CLIENT_VERSION:
 *
 * The Steam client version.
 */
#define STEAM_API_CLIENT_VERSION  "3472020 (2.1.6)"

/**
 * STEAM_API_TIMEOUT:
 *
 * The timeout (in seconds) of a poll request. This value should not
 * exceed `25`. Higher values result in frequent HTTP 500 responses.
 */
#define STEAM_API_TIMEOUT  25

/**
 * STEAM_API_IDLEOUT_AWAY:
 *
 * The idle time (in seconds) required for being "away."
 */
#define STEAM_API_IDLEOUT_AWAY  600

/**
 * STEAM_API_IDLEOUT_SNOOZE:
 *
 * The idle time (in seconds) required for "snoozing."
 */
#define STEAM_API_IDLEOUT_SNOOZE  8000

/**
 * STEAM_API_PATH_FRIEND_SEARCH:
 *
 * The Steam API path for the friend search request.
 */
#define STEAM_API_PATH_FRIEND_SEARCH  "/ISteamUserOAuth/Search/v0001"

/**
 * STEAM_API_PATH_FRIENDS:
 *
 * The Steam API path for the friends request.
 */
#define STEAM_API_PATH_FRIENDS  "/ISteamUserOAuth/GetFriendList/v0001"

/**
 * STEAM_API_PATH_LOGON:
 *
 * The Steam API path for the logon request.
 */
#define STEAM_API_PATH_LOGON  "/ISteamWebUserPresenceOAuth/Logon/v0001"

/**
 * STEAM_API_PATH_LOGOFF:
 *
 * The Steam API path for the logoff request.
 */
#define STEAM_API_PATH_LOGOFF  "/ISteamWebUserPresenceOAuth/Logoff/v0001"

/**
 * STEAM_API_PATH_MESSAGE:
 *
 * The Steam API path for the message request.
 */
#define STEAM_API_PATH_MESSAGE  "/ISteamWebUserPresenceOAuth/Message/v0001"

/**
 * STEAM_API_PATH_MESSAGE_INFO:
 *
 * The Steam API path for the message information request.
 */
#define STEAM_API_PATH_MESSAGE_INFO  "/IFriendMessagesService/GetActiveMessageSessions/v0001"

/**
 * STEAM_API_PATH_MESSAGES:
 *
 * The Steam API path for the messages request.
 */
#define STEAM_API_PATH_MESSAGES  "/IFriendMessagesService/GetRecentMessages/v0001"

/**
 * STEAM_API_PATH_MESSAGES_READ:
 *
 * The Steam API path for the messages read request.
 */
#define STEAM_API_PATH_MESSAGES_READ  "/IFriendMessagesService/MarkOfflineMessagesRead/v0001"

/**
 * STEAM_API_PATH_POLL:
 *
 * The Steam API path for the poll request.
 */
#define STEAM_API_PATH_POLL  "/ISteamWebUserPresenceOAuth/Poll/v0001"

/**
 * STEAM_API_PATH_SUMMARIES:
 *
 * The Steam API path for the summaries request.
 */
#define STEAM_API_PATH_SUMMARIES  "/ISteamUserOAuth/GetUserSummaries/v0001"

/**
 * STEAM_COM_PATH_AUTH:
 *
 * The Steam Community path for the authentication request.
 */
#define STEAM_COM_PATH_AUTH  "/mobilelogin/dologin/"

/**
 * STEAM_COM_PATH_AUTH:
 *
 * The Steam Community path for the authentication request.
 */
#define STEAM_COM_PATH_AUTH_RDIR  "/mobileloginsucceeded/"

/**
 * STEAM_COM_PATH_CAPTCHA:
 *
 * The Steam Community path for the captcha image.
 */
#define STEAM_COM_PATH_CAPTCHA  "/public/captcha.php"

/**
 * STEAM_COM_PATH_CHATLOG:
 *
 * The Steam Community path for the chat log request.
 */
#define STEAM_COM_PATH_CHATLOG  "/chat/chatlog/"

/**
 * STEAM_COM_PATH_FRIEND_ADD:
 *
 * The Steam Community path for the friend add request.
 */
#define STEAM_COM_PATH_FRIEND_ADD  "/actions/AddFriendAjax/"

/**
 * STEAM_COM_PATH_FRIEND_BLOCK:
 *
 * The Steam Community path for the friend block request.
 */
#define STEAM_COM_PATH_FRIEND_BLOCK  "/actions/BlockUserAjax/"

/**
 * STEAM_COM_PATH_FRIEND_REMOVE:
 *
 * The Steam Community path for the friend remove request.
 */
#define STEAM_COM_PATH_FRIEND_REMOVE  "/actions/RemoveFriendAjax/"

/**
 * STEAM_COM_PATH_KEY:
 *
 * The Steam Community path for the public key request.
 */
#define STEAM_COM_PATH_KEY  "/mobilelogin/getrsakey/"

/**
 * STEAM_API_ERROR:
 *
 * The #GQuark of the domain of API errors.
 */
#define STEAM_API_ERROR  steam_api_error_quark()

typedef struct _SteamApi SteamApi;
typedef struct _SteamApiReq SteamApiReq;

/**
 * SteamApiFunc:
 * @req: The #SteamApiReq.
 * @data: The user defined data or #NULL.
 *
 * The callback for #SteamApiReq operations.
 */
typedef void (*SteamApiFunc) (SteamApiReq *req, gpointer data);

/**
 * SteamApiParser:
 * @req: The #SteamApiReq.
 * @json: The #json_value or #NULL.
 *
 * The callback for parser based #SteamApiReq operations.
 */
typedef void (*SteamApiParser) (SteamApiReq *req, const json_value *json);

/**
 * SteamApiAuthType:
 * @STEAM_API_AUTH_TYPE_EMAIL: SteamGuard via email.
 * @STEAM_API_AUTH_TYPE_MOBILE: SteamGuard via mobile.
 *
 * The authentication types.
 */
typedef enum
{
    STEAM_API_AUTH_TYPE_EMAIL,
    STEAM_API_AUTH_TYPE_MOBILE
} SteamApiAuthType;

/**
 * SteamApiError:
 * @STEAM_API_ERROR_CAPTCHA: Captcha required.
 * @STEAM_API_ERROR_EXPRIED: Session expired.
 * @STEAM_API_ERROR_GENERAL: General failure.
 * @STEAM_API_ERROR_PARSER: Parsing failure.
 * @STEAM_API_ERROR_STEAMGUARD: SteamGuard required.
 * @STEAM_API_ERROR_UNKNOWN: Unknown failure.
 *
 * The error codes for the #STEAM_API_ERROR domain.
 */
typedef enum
{
    STEAM_API_ERROR_CAPTCHA,
    STEAM_API_ERROR_EXPRIED,
    STEAM_API_ERROR_GENERAL,
    STEAM_API_ERROR_PARSER,
    STEAM_API_ERROR_STEAMGUARD,
    STEAM_API_ERROR_UNKNOWN
} SteamApiError;

/**
 * SteamApiReqFlags:
 * @STEAM_API_REQ_FLAG_NOJSON: Skip JSON parsing.
 *
 * The #SteamApiReq flags.
 */
typedef enum
{
    STEAM_API_REQ_FLAG_NOJSON = 1 << 0
} SteamApiReqFlags;

/**
 * SteamApiAcceptType:
 * @STEAM_API_ACCEPT_TYPE_DEFAULT: Accept the request.
 * @STEAM_API_ACCEPT_TYPE_BLOCK: Block the other user.
 * @STEAM_API_ACCEPT_TYPE_IGNORE: Ignore the request.
 *
 * The friend acceptance types.
 */
typedef enum
{
    STEAM_API_ACCEPT_TYPE_DEFAULT = 0,
    STEAM_API_ACCEPT_TYPE_BLOCK,
    STEAM_API_ACCEPT_TYPE_IGNORE
} SteamApiAcceptType;

/**
 * SteamApi:
 * @info: The #SteamUserInfo of the user.
 * @http: The #SteamHttp for API requests.
 * @msgs: The #GQueue of message based #SteamApiReq.
 * @online: The online state of the user.
 * @idle: The idle time of the user.
 * @umqid: The unique device identifier.
 * @token: The session token (mobile requests).
 * @sessid: The session identifier (community requests).
 * @lmid: The last message identifier.
 * @time: The logon timestamp (UTC).
 * @autht: The #SteamApiAuthType.
 * @cgid: The captcha GID (authentication).
 * @esid: The email SteamID (authentication).
 * @pkmod: The PKCS (RSA) modulus (authentication).
 * @pkexp: The PKCS (RSA) exponent (authentication).
 * @pktime: The PKCS (RSA) key time (authentication).
 *
 * Represents a Steam connection.
 */
struct _SteamApi
{
    SteamUserInfo *info;
    SteamHttp *http;
    GQueue *msgs;
    gboolean online;
    guint32 idle;

    gchar *umqid;
    gchar *token;
    gchar *sessid;
    gint64 lmid;
    gint64 time;

    SteamApiAuthType autht;
    gchar *cgid;
    gchar *esid;
    gchar *pkmod;
    gchar *pkexp;
    gchar *pktime;
};

/**
 * SteamApiReq:
 * @api: The #SteamApi.
 * @flags: The #SteamApiReqFlags.
 * @req: The #SteamHttpReq.
 * @err: The #GError or #NULL.
 * @msgs: The #GQueue of #SteamApiMsg.
 * @infs: The #GQueue of #SteamUserInfo.
 * @infr: The #GQueue of #SteamUserInfo remaining.
 * @func: The #SteamApiFunc or #NULL.
 * @data: The user define data or #NULL.
 * @punc: The #SteamApiParser or #NULL.
 *
 * Represents a Steam request.
 */
struct _SteamApiReq
{
    SteamApi *api;
    SteamApiReqFlags flags;
    SteamHttpReq *req;

    GError *err;
    GQueue *msgs;
    GQueue *infs;
    GQueue *infr;

    SteamApiFunc func;
    gpointer data;
    SteamApiParser punc;
};

/**
 * steam_api_error_quark:
 *
 * Gets the #GQuark of the domain of API errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
steam_api_error_quark(void);

/**
 * steam_api_new:
 *
 * Creates a new #SteamApi. The returned #SteamApi should be freed with
 * #steam_api_free() when no longer needed.
 *
 * Returns: The #SteamApi.
 */
SteamApi *
steam_api_new(void);

/**
 * steam_api_free_auth:
 * @api: The #SteamApi.
 *
 * Frees all memory used by the #SteamApi for authentication.
 */
void
steam_api_free_auth(SteamApi *api);

/**
 * steam_api_free:
 * @api: The #SteamApi.
 *
 * Frees all memory used by the #SteamApi.
 */
void
steam_api_free(SteamApi *api);

/**
 * steam_api_captcha_url:
 * @cgid: The captcha GID.
 *
 * Gets the captcha URL for the captcha GID. The returned string should
 * be freed with #g_free() when no longer needed.
 *
 * Returns: The captcha URL or #NULL on error.
 */
gchar *
steam_api_captcha_url(const gchar *cgid);

/**
 * steam_api_rehash:
 * @api: The #SteamApi.
 *
 * Rehashes and updates internal data of the #SteamApi. This should be
 * called whenever properties are modified.
 */
void
steam_api_rehash(SteamApi *api);

/**
 * steam_api_req_new:
 * @api: The #SteamApi.
 * @func: The #SteamApiFunc or #NULL.
 * @data: The user defined data or #NULL.
 *
 * Creates a new #SteamApiReq. The returned #SteamApiReq should be
 * freed with #steam_api_req_free() when no longer needed.
 *
 * Returns: The #SteamApiReq.
 */
SteamApiReq *
steam_api_req_new(SteamApi *api, SteamApiFunc func, gpointer data);

/**
 * steam_api_req_fwd:
 * @req: The #SteamApiReq.
 *
 * Creates a new forwarded #SteamApiReq. This NULLs the err, func,
 * data, msgs, infs, and infr data fields in the source #SteamApiReq,
 * and forwards them to the return #SteamApiReq. The returned
 * #SteamApiReq should be free with #steam_api_req_free() when no
 * longer needed.
 *
 * Returns: The #SteamApiReq.
 */
SteamApiReq *
steam_api_req_fwd(SteamApiReq *req);

/**
 * steam_api_req_free:
 * @req: The #SteamApiReq.
 *
 * Frees all memory used by the #SteamApiReq.
 */
void
steam_api_req_free(SteamApiReq *req);

/**
 * steam_api_req_init:
 * @req: The #SteamApiReq.
 * @host: The request hostname.
 * @path: The request pathname.
 *
 * Initializes a new SSL based #SteamHttpReq for the #SteamApiReq.
 */
void
steam_api_req_init(SteamApiReq *req, const gchar *host, const gchar *path);

/**
 * steam_api_req_auth:
 * @req: The #SteamApiReq.
 * @user: The username.
 * @pass: The password.
 * @authcode: The authorization code (Steam Guard) or #NULL.
 * @captcha: The captcha code or #NULL.
 *
 * Sends na authorization request. This is typically called twice to
 * complete the authorization process. First, the user is authenticated
 * partially, and then the Steam Guard code is requested. Then, with the
 * Steam Guard code, the authentication process can be completed.
 */
void
steam_api_req_auth(SteamApiReq *req, const gchar *user, const gchar *pass,
                   const gchar *authcode, const gchar *captcha);

/**
 * steam_api_req_friends:
 * @req: The #SteamApiReq.
 *
 * Sends a friend list request. This returns the entire list of friends
 * for the #SteamApi user, including ignored friends.
 */
void
steam_api_req_friends(SteamApiReq *req);

/**
 * steam_api_req_key:
 * @req: The #SteamApiReq.
 * @user: The username.
 *
 * Sends a key request. The PKCS key is used to encrypt the password
 * before it is sent during the authentication phase.
 */
void
steam_api_req_key(SteamApiReq *req, const gchar *user);

/**
 * steam_api_req_logoff:
 * @req: The #SteamApiReq.
 *
 * Sends a logoff request. This simply logs the #SteamApi user off.
 */
void
steam_api_req_logoff(SteamApiReq *req);

/**
 * steam_api_req_logon:
 * @req: The #SteamApiReq.
 *
 * Sends a logon request. This simply logs the #SteamApi user on. The
 * #SteamApi user must be authenticated via #steam_api_req_auth()
 * before they can logon.
 */
void
steam_api_req_logon(SteamApiReq *req);

/**
 * steam_api_req_msg:
 * @req: The #SteamApiReq.
 * @msg: The #SteamUserMsg.
 *
 * Sends a message request. This sends a #SteamUserMsg to a Steam user.
 */
void
steam_api_req_msg(SteamApiReq *req, const SteamUserMsg *msg);

/**
 * steam_api_req_msg_info:
 * @req: The #SteamApiReq.
 *
 * Sends a message information request. This retrieves the last know
 * message info of the #SteamUserInfos.
 */
void
steam_api_req_msg_info(SteamApiReq *req);

/**
 * steam_api_req_msgs:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 * @since: The since timestamp.
 *
 * Sends a message log request.
 */
void
steam_api_req_msgs(SteamApiReq *req, SteamId id, gint64 since);

/**
 * steam_api_req_msgs_read:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 *
 * Sends a messages read request.
 */
void
steam_api_req_msgs_read(SteamApiReq *req, SteamId id);

/**
 * steam_api_req_poll:
 * @req: The #SteamApiReq.
 *
 * Sends a poll request. This retrieves new messages from Steam. In
 * addition, this keeps the #SteamApi session active, and must be
 * called every 30 seconds.
 */
void
steam_api_req_poll(SteamApiReq *req);

/**
 * steam_api_req_user_accept:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 * @type: The #SteamApiAcceptType.
 *
 * Sends a friend accept request. If someone has requested friendship
 * with the #SteamApi user, this will accept the friendship request.
 */
void
steam_api_req_user_accept(SteamApiReq *req, SteamId id,
                          SteamApiAcceptType type);

/**
 * steam_api_req_user_add:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 *
 * Sends a friend add request. This will request the friendship of
 * another Steam user. The Steam user is not really a friend until
 * they accept the request on their end.
 */
void
steam_api_req_user_add(SteamApiReq *req, SteamId id);

/**
 * steam_api_req_user_ignore:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 * @ignore: #TRUE to ignore, otherwise #FALSE.
 *
 * Sends a friend ignore request. This will either ignore or unignore
 * a Steam user from the #SteamApi user.
 */
void
steam_api_req_user_ignore(SteamApiReq *req, SteamId id, gboolean ignore);

/**
 * steam_api_req_user_info:
 * @req: The #SteamApiReq.
 *
 * Sends a user information request. This retrieves the user information
 * for all users in the #SteamApiReq->infos list.
 */
void
steam_api_req_user_info(SteamApiReq *req);

/**
 * steam_api_req_user_info_nicks:
 * @req: The #SteamApiReq.
 *
 * Sends a user nickname information request. This retrieves the user
 * nicname information for all users in the #SteamApiReq->infos list.
 */
void
steam_api_req_user_info_nicks(SteamApiReq *req);

/**
 * steam_api_req_user_remove:
 * @req: The #SteamApiReq.
 * @id: The #SteamId.
 *
 * Sends a friend remove request. This will remove a Steam friend from
 * the friend list of the #SteamApi user. This does not block the user,
 * see: #steam_api_req_user_ignore().
 */
void
steam_api_req_user_remove(SteamApiReq *req, SteamId id);

/**
 * steam_api_req_user_search:
 * @req: The #SteamApiReq.
 * @name: The username.
 * @count: The amount of search results.
 *
 * Sends a user search request. This searches for Steam users based on
 * a search term. This is very useful when attempting to add Steam
 * users by their name via #steam_api_req_user_add().
 */
void
steam_api_req_user_search(SteamApiReq *req, const gchar *name, guint count);

#endif /* _STEAM_API_H_ */
