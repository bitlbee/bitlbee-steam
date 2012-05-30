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

#include <bitlbee/bitlbee.h>

#define STEAM_API_HOST      "api.steampowered.com"
#define STEAM_API_AGENT     "Steam 1291812 / iPhone"

#define STEAM_PATH_AUTH     "/ISteamOAuth2/GetTokenWithCredentials/v0001"
#define STEAM_PATH_LOGON    "/ISteamWebUserPresenceOAuth/Logon/v0001"
#define STEAM_PATH_LOGOFF   "/ISteamWebUserPresenceOAuth/Logoff/v0001"
#define STEAM_PATH_POLL     "/ISteamWebUserPresenceOAuth/PollStatus/v0001"


typedef enum   _SteamError SteamError;
typedef struct _SteamAPI   SteamAPI;

typedef void (*SteamAPIFunc) (SteamAPI * api, SteamError err, gpointer data);

enum _SteamError
{
    STEAM_ERROR_SUCCESS = 0,
    STEAM_ERROR_GENERIC,
    
    STEAM_ERROR_AUTH_CODE_INVALID,
    STEAM_ERROR_AUTH_CODE_REQ,
    STEAM_ERROR_AUTH_FAILED,
    
    STEAM_ERROR_JSON_EMPTY,
    STEAM_ERROR_JSON_PARSE,
    
    STEAM_ERROR_LOGON_FAILED,
    STEAM_ERROR_LOGON_INVALID,
    
    STEAM_ERROR_LOGOFF_FAILED,
    
    STEAM_ERROR_MESSAGE_EMPTY,
    STEAM_ERROR_STEAMID_EMPTY,
    
    STEAM_ERROR_UMQID_MISMATCH,
    STEAM_ERROR_UMQID_EMPTY
};

struct _SteamAPI
{
    account_t * acc;
    
    gchar *token;
    gchar *steamid;
    gchar *umqid;
    gchar *message;
};


gchar *steam_api_error_str(SteamError err);

SteamAPI *steam_api_new(account_t *acc);

void steam_api_free(SteamAPI *api);

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    SteamAPIFunc func, gpointer data);

void steam_api_friends(SteamAPI *api, SteamAPIFunc func, gpointer data);

void steam_api_logon(SteamAPI *api, SteamAPIFunc func, gpointer data);

void steam_api_logoff(SteamAPI *api, SteamAPIFunc func, gpointer data);

void steam_api_poll(SteamAPI *api, SteamAPIFunc func, gpointer data);


#endif /* _STEAM_API_H */
