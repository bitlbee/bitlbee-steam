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

#include <bitlbee.h>

#define STEAM_API_HOST        "api.steampowered.com"
#define STEAM_API_AGENT       "Steam 1291812 / iPhone"

#define STEAM_PATH_AUTH       "/ISteamOAuth2/GetTokenWithCredentials/v0001"
#define STEAM_PATH_LOGON      "/ISteamWebUserPresenceOAuth/Logon/v0001"
#define STEAM_PATH_LOGOFF     "/ISteamWebUserPresenceOAuth/Logoff/v0001"
#define STEAM_PATH_MESSAGE    "/ISteamWebUserPresenceOAuth/Message/v0001"
#define STEAM_PATH_POLL       "/ISteamWebUserPresenceOAuth/Poll/v0001"
#define STEAM_PATH_USER_INFO  "/ISteamUserOAuth/GetUserSummaries/v0001"


typedef enum   _SteamError       SteamError;
typedef enum   _SteamState       SteamState;
typedef enum   _SteamMessageType SteamMessageType;
typedef struct _SteamAPI         SteamAPI;
typedef struct _SteamMessage     SteamMessage;
typedef struct _SteamUserInfo    SteamUserInfo;

typedef void (*SteamAPIFunc)      (SteamAPI *api, SteamError err,
                                   gpointer data);

typedef void (*SteamPollFunc)     (SteamAPI *api, GSList *m_updates,
                                   SteamError err, gpointer data);

typedef void (*SteamUserInfoFunc) (SteamAPI *api, SteamUserInfo *uinfo,
                                   SteamError err, gpointer data);

enum _SteamError
{
    STEAM_ERROR_SUCCESS = 0,
    STEAM_ERROR_GENERIC,

    STEAM_ERROR_EMPTY_MESSAGE,
    STEAM_ERROR_EMPTY_STEAMID,
    STEAM_ERROR_EMPTY_UMQID,
    STEAM_ERROR_EMPTY_USER_INFO,
    STEAM_ERROR_EMPTY_XML,

    STEAM_ERROR_FAILED_AUTH,
    STEAM_ERROR_FAILED_LOGOFF,
    STEAM_ERROR_FAILED_LOGON,
    STEAM_ERROR_FAILED_MESSAGE_SEND,
    STEAM_ERROR_FAILED_POLL,

    STEAM_ERROR_INVALID_AUTH_CODE,
    STEAM_ERROR_INVALID_LOGON,

    STEAM_ERROR_MISMATCH_UMQID,
    STEAM_ERROR_NOT_AUTHORIZED,
    STEAM_ERROR_PARSE_XML,
    STEAM_ERROR_REQ_AUTH_CODE
};

enum _SteamState
{
    STEAM_STATE_OFFLINE = 0,
    STEAM_STATE_ONLINE  = 1,
    STEAM_STATE_BUSY    = 2,
    STEAM_STATE_AWAY    = 3,
    STEAM_STATE_SNOOZE  = 4
};

enum _SteamMessageType
{
    STEAM_MESSAGE_TYPE_SAYTEXT = 0,
    STEAM_MESSAGE_TYPE_EMOTE,
    STEAM_MESSAGE_TYPE_LEFT_CONV,
    STEAM_MESSAGE_TYPE_STATE,
    STEAM_MESSAGE_TYPE_TYPING
};

struct _SteamAPI
{
    account_t * acc;

    gchar *token;
    gchar *steamid;
    gchar *umqid;
    gchar *lmid;
};

struct _SteamMessage
{
    SteamMessageType type;

    const gchar *steamid;
    const gchar *text;

    SteamState state;
    const gchar *name;
};

struct _SteamUserInfo
{
    const gchar *steamid;
    SteamState state;

    const gchar *name;
    const gchar *realname;
    const gchar *profile;
};


SteamAPI *steam_api_new(account_t *acc, const gchar *umqid);

void steam_api_free(SteamAPI *api);

void steam_api_message(SteamAPI *api, const gchar *steamid,
                       const gchar *message, SteamMessageType type,
                       SteamAPIFunc func, gpointer data);

void steam_api_logon(SteamAPI *api, SteamAPIFunc func, gpointer data);

void steam_api_logoff(SteamAPI *api, SteamAPIFunc func, gpointer data);

void steam_api_poll(SteamAPI *api, SteamPollFunc func, gpointer data);

void steam_api_user_info(SteamAPI *api, gchar *steamid, SteamUserInfoFunc func,
                         gpointer data);

gchar *steam_api_error_str(SteamError err);

gchar *steam_message_type_str(SteamMessageType type);

gchar *steam_state_str(SteamState state);


#endif /* _STEAM_API_H */
