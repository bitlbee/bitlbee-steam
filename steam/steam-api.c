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

#include <bitlbee/http_client.h>
#include <glib-object.h>
#include <json.h>

#include "steam-api.h"

#ifndef json_bool

typedef int json_bool;

#endif

#ifndef json_object_object_get_ex

static json_bool json_object_object_get_ex(json_object *jo, const char *key,
                                           json_object **value)
{
    *value = json_object_object_get(jo, key);
    return (*value != NULL);
}

#endif

#define steam_api_func(p, e) \
    if(p->func != NULL) \
        (((SteamAPIFunc) p->func) (p->api, e, p->data))

#define steam_poll_func(p, pu, mu, t, e) \
    if(p->func != NULL) \
        (((SteamPollFunc) p->func) (p->api, pu, mu, t, e, p->data))
                                      
#define steam_user_info_func(p, i, e) \
    if(p->func != NULL) \
        (((SteamUserInfoFunc) p->func) (p->api, i, e, p->data))


typedef enum   _SteamPairType SteamPairType;
typedef struct _SteamPair     SteamPair;
typedef struct _SteamFuncPair SteamFuncPair;

enum _SteamPairType
{
    STEAM_PAIR_AUTH,
    STEAM_PAIR_LOGON,
    STEAM_PAIR_LOGOFF,
    STEAM_PAIR_MESSAGE,
    STEAM_PAIR_POLL,
    STEAM_PAIR_USER_INFO
};

struct _SteamPair
{
    const gchar *key;
    const gchar *value;
};

struct _SteamFuncPair
{
    SteamPairType type;
    SteamAPI *api;
    
    gpointer func;
    gpointer data;
};

static SteamFuncPair *steam_pair_new(SteamPairType type, SteamAPI *api,
                                     gpointer func, gpointer data)
{
    SteamFuncPair *fp;
    
    fp = g_new0(SteamFuncPair, 1);
    fp->type = type;
    fp->api  = api;
    fp->func = func;
    fp->data = data;
    
    return fp;
}

SteamAPI *steam_api_new(account_t *acc)
{
    SteamAPI *api;
    
    g_return_val_if_fail(acc != NULL, NULL);
    
    api = g_new0(SteamAPI, 1);
    api->acc = acc;
    
    return api;
}

void steam_api_free(SteamAPI *api)
{
    g_return_if_fail(api != NULL);
    
    g_free(api->token);
    g_free(api->steamid);
    g_free(api->umqid);
    
    g_free(api);
}

static void steam_api_auth_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    if(json_object_object_get_ex(jo, "access_token", &so)) {
        sm = json_object_get_string(so);
        
        g_free(fp->api->token);
        fp->api->token = g_strdup(sm);
        
        steam_api_func(fp, STEAM_ERROR_SUCCESS);
    } else if(json_object_object_get_ex(jo, "x_errorcode", &so)) {
        sm = json_object_get_string(so);
        
        if(!g_strcmp0("steamguard_code_required", sm))
            steam_api_func(fp, STEAM_ERROR_REQ_AUTH_CODE);
        else if(!g_strcmp0("invalid_steamguard_code", sm))
            steam_api_func(fp, STEAM_ERROR_INVALID_AUTH_CODE);
        else
            steam_api_func(fp, STEAM_ERROR_FAILED_AUTH);
    } else {
        steam_api_func(fp, STEAM_ERROR_FAILED_AUTH);
    }
}

static void steam_api_logon_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    if(!json_object_object_get_ex(jo, "umqid", &so)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_UMQID);
        return;
    }
    
    sm = json_object_get_string(so);
    
    if(g_strcmp0(fp->api->umqid, sm)) {
        steam_api_func(fp, STEAM_ERROR_MISMATCH_UMQID);
        return;
    }
    
    if(!json_object_object_get_ex(jo, "steamid", &so)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_STEAMID);
        return;
    }
    
    sm = json_object_get_string(so);
    
    g_free(fp->api->steamid);
    fp->api->steamid = g_strdup(sm);
    
    if(!json_object_object_get_ex(jo, "message", &so)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_MESSAGE);
        return;
    }
    
    sm = json_object_get_string(so);
    
    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(sm);
    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_logoff_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    if(json_object_object_get_ex(jo, "error", &so)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_LOGOFF);
        return;
    }
    
    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_message_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    if(!json_object_object_get_ex(jo, "error", &so)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }
    
    sm = json_object_get_string(so);
    
    if(g_strcmp0("OK", sm)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }
    
    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_poll_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so, *se, *sv;
    SteamPersona *sp;
    SteamUserMessage *um;
    
    const gchar *sm, *id;
    gint len, si, i;
    gint to;
    
    GSList *mu = NULL;
    GSList *pu = NULL;
    
    if(!json_object_object_get_ex(jo, "sectimeout", &so)) {
        steam_poll_func(fp, pu, mu, 3000, STEAM_ERROR_FAILED_POLL);
        return;
    }
    
    to = json_object_get_int(so);
    to = ((to >= 1) && (to <= 30)) ? (to * 1000) : 3000;
    
    if(!json_object_object_get_ex(jo, "messagelast", &so)) {
        steam_poll_func(fp, pu, mu, to, STEAM_ERROR_SUCCESS);
        return;
    }
    
    sm = json_object_get_string(so);
    
    if(!g_strcmp0(fp->api->lmid, sm)) {
        steam_poll_func(fp, pu, mu, to, STEAM_ERROR_SUCCESS);
        return;
    }
    
    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(sm);
    
    if(!json_object_object_get_ex(jo, "messages", &so)) {
        steam_poll_func(fp, pu, mu, to, STEAM_ERROR_SUCCESS);
        return;
    }
    
    if(json_object_get_type(so) != json_type_array) {
        steam_poll_func(fp, pu, mu, to, STEAM_ERROR_SUCCESS);
        return;
    }
    
    len = json_object_array_length(so);
    
    for(i = 0; i < len; i++) {
        se = json_object_array_get_idx(so, i);
        
        if(!json_object_object_get_ex(se, "type", &sv))
            continue;
        
        sm = json_object_get_string(sv);
        
        if(!json_object_object_get_ex(se, "steamid_from", &sv))
            continue;
        
        id = json_object_get_string(sv);
        
        if(!g_strcmp0(fp->api->steamid, id))
            continue;
        
        if(!g_strcmp0("saytext", sm)) {
            if(!json_object_object_get_ex(se, "text", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            um = g_new0(SteamUserMessage, 1);
            mu = g_slist_append(mu, um);
            
            um->type    = STEAM_MESSAGE_TYPE_SAYTEXT;
            um->steamid = id;
            um->message = sm;
        } else if(!g_strcmp0("emote", sm)) {
            if(!json_object_object_get_ex(se, "text", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            um = g_new0(SteamUserMessage, 1);
            mu = g_slist_append(mu, um);
            
            um->type    = STEAM_MESSAGE_TYPE_EMOTE;
            um->steamid = id;
            um->message = sm;
        } else if(!g_strcmp0("personastate", sm)) {
            if(!json_object_object_get_ex(se, "persona_name", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            
            if(!json_object_object_get_ex(se, "persona_state", &sv))
                continue;
            
            si = json_object_get_int(sv);
            sp = g_new0(SteamPersona, 1);
            pu = g_slist_append(pu, sp);
            
            sp->steamid = id;
            sp->state   = si;
            sp->name    = sm;
        }
    }
    
    steam_poll_func(fp, pu, mu, to, STEAM_ERROR_SUCCESS);
    
    g_slist_free_full(mu, g_free);
    g_slist_free_full(pu, g_free);
}

static void steam_api_user_info_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so, *sv;
    SteamUserInfo info;
    
    memset(&info, 0, sizeof (SteamUserInfo));
    
    if(!json_object_object_get_ex(jo, "players", &so)) {
        steam_user_info_func(fp, &info, STEAM_ERROR_EMPTY_USER_INFO);
        return;
    }
    
    if(json_object_get_type(so) != json_type_array) {
        steam_user_info_func(fp, &info, STEAM_ERROR_EMPTY_USER_INFO);
        return;
    }
    
    if(json_object_array_length(so) < 1) {
        steam_user_info_func(fp, &info, STEAM_ERROR_EMPTY_USER_INFO);
        return;
    }
    
    so = json_object_array_get_idx(so, 0);
    
    if(json_object_object_get_ex(so, "steamid", &sv))
        info.steamid  = json_object_get_string(sv);
    
    if(json_object_object_get_ex(so, "personastate", &sv))
        info.state    = json_object_get_int(sv);
    
    if(json_object_object_get_ex(so, "personaname", &sv))
        info.name     = json_object_get_string(sv);
    
    if(json_object_object_get_ex(so, "realname", &sv))
        info.realname = json_object_get_string(sv);
    
    if(json_object_object_get_ex(so, "profileurl", &sv))
        info.profile  = json_object_get_string(sv);
    
    steam_user_info_func(fp, &info, STEAM_ERROR_SUCCESS);
}

static void steam_api_cb(struct http_request *req)
{
    SteamFuncPair *fp = req->data;
    json_tokener *jt;
    json_object  *jo;
    
    if((req->status_code != 200) || (req->reply_body == NULL)) {
        switch(fp->type) {
        case STEAM_PAIR_AUTH:
        case STEAM_PAIR_LOGON:
        case STEAM_PAIR_LOGOFF:
        case STEAM_PAIR_MESSAGE:
            steam_api_func(fp, STEAM_ERROR_EMPTY_JSON);
            break;
        
        case STEAM_PAIR_POLL:
            steam_poll_func(fp, NULL, NULL, 3000, STEAM_ERROR_SUCCESS);
            break;
        
        case STEAM_PAIR_USER_INFO:
            steam_user_info_func(fp, NULL, STEAM_ERROR_EMPTY_JSON);
            break;
        }
        
        g_free(fp);
        return;
    }
    
    jt = json_tokener_new();
    jo = json_tokener_parse_ex(jt, req->reply_body, req->body_size);
    
    switch(fp->type) {
    case STEAM_PAIR_AUTH:
        steam_api_auth_cb(fp, jo);
        break;
    
    case STEAM_PAIR_LOGON:
        steam_api_logon_cb(fp, jo);
        break;
    
    case STEAM_PAIR_LOGOFF:
        steam_api_logoff_cb(fp, jo);
        break;
    
    case STEAM_PAIR_MESSAGE:
        steam_api_message_cb(fp, jo);
        break;
    
    case STEAM_PAIR_POLL:
        steam_api_poll_cb(fp, jo);
        break;
    
    case STEAM_PAIR_USER_INFO:
        steam_api_user_info_cb(fp, jo);
        break;
    }
    
    json_object_put(jo);
    json_tokener_free(jt);
    g_free(fp);
}

static void steam_api_req(const gchar *path, SteamPair *params, gint psize,
                          gboolean ssl, gboolean post, SteamFuncPair *fp)
{
    gchar *rd = NULL;
    gsize len = 0;
    gchar *req;
    
    if(psize >= 1) {
        gchar **sp, *esc;
        guint i;
        
        sp = g_new0(gchar*, (psize + 1));
        
        for(i = 0; i < psize; i++) {
            if(params[i].value == NULL)
                params[i].value = "";
            
            esc   = g_uri_escape_string(params[i].value, NULL, FALSE);
            sp[i] = g_strdup_printf("%s=%s", params[i].key, esc);
            
            g_free(esc);
        }
        
        rd  = g_strjoinv("&", sp);
        len = strlen(rd);
        
        g_strfreev(sp);
    }
    
    if(post) {
        req = g_strdup_printf(
            "POST %s HTTP/1.1\r\n"
            "User-Agent: " STEAM_API_AGENT "\r\n"
            "Host: " STEAM_API_HOST "\r\n"
            "Accept: */*\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "content-length: %u\r\n"
            "Connection: close\r\n"
            "\r\n%s", path, len, rd);
    } else {
        req = g_strdup_printf(
            "GET %s?%s HTTP/1.1\r\n"
            "User-Agent: " STEAM_API_AGENT "\r\n"
            "Host: " STEAM_API_HOST "\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n", path, rd);
    }
    
    http_dorequest(STEAM_API_HOST, (ssl ? 443 : 80), ssl, req,
                   steam_api_cb, fp);
    
    g_free(rd);
    g_free(req);
}

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    SteamAPIFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);
    
    SteamPair ps[7] = {
        {"client_id",       "DE45CD61"},
        {"grant_type",      "password"},
        {"username",        api->acc->user},
        {"password",        api->acc->pass},
        {"x_emailauthcode", authcode},
        {"x_webcookie",     ""},
        {"scope",           "read_profile write_profile "
                            "read_client write_client"}
    };
    
    steam_api_req(STEAM_PATH_AUTH, ps, 7, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_AUTH, api, func, data));
}

void steam_api_logon(SteamAPI *api, SteamAPIFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);
    
    SteamPair ps[2] = {
        {"access_token", api->token},
        {"umqid",        api->umqid}
    };
    
    steam_api_req(STEAM_PATH_LOGON, ps, 2, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_LOGON, api, func, data));
}

void steam_api_logoff(SteamAPI *api, SteamAPIFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);
    
    SteamPair ps[2] = {
        {"access_token", api->token},
        {"umqid",        api->umqid}
    };
    
    steam_api_req(STEAM_PATH_LOGOFF, ps, 2, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_LOGOFF, api, func, data));
}

void steam_api_message(SteamAPI *api, const gchar *steamid,
                       const gchar *message, SteamMessageType type,
                       SteamAPIFunc func, gpointer data)
{
    gchar *stype;
    
    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);
    
    stype = steam_message_type_str(type);
    
    SteamPair ps[5] = {
        {"access_token", api->token},
        {"umqid",        api->umqid},
        {"steamid_dst",  steamid},
        {"type",         stype},
        {"text",         message}
    };
    
    steam_api_req(STEAM_PATH_MESSAGE, ps, 5, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_MESSAGE, api, func, data));
}

void steam_api_poll(SteamAPI *api, SteamPollFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);
    
    SteamPair ps[3] = {
        {"access_token", api->token},
        {"umqid",        api->umqid},
        {"message",      api->lmid}
    };
    
    steam_api_req(STEAM_PATH_POLL, ps, 3, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_POLL, api, func, data));
}

void steam_api_user_info(SteamAPI *api, gchar *steamid, SteamUserInfoFunc func,
                         gpointer data)
{
    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);
    
    SteamPair ps[2] = {
        {"access_token", api->token},
        {"steamids",     steamid}
    };
    
    steam_api_req(STEAM_PATH_USER_INFO, ps, 2, TRUE, FALSE,
                  steam_pair_new(STEAM_PAIR_USER_INFO, api, func, data));
}

gchar *steam_api_error_str(SteamError err)
{
    switch(err) {
    case STEAM_ERROR_SUCCESS:
        return "Success";
    case STEAM_ERROR_GENERIC:
        return "Something has gone terribly wrong";
    case STEAM_ERROR_EMPTY_JSON:
        return "Failed to receive JSON reply";
    case STEAM_ERROR_EMPTY_MESSAGE:
        return "Empty message";
    case STEAM_ERROR_EMPTY_STEAMID:
        return "Empty SteamID";
    case STEAM_ERROR_EMPTY_UMQID:
        return "Empty UMQID";
    case STEAM_ERROR_EMPTY_USER_INFO:
        return "Empty user information";
    case STEAM_ERROR_FAILED_AUTH:
        return "Authentication failed";
    case STEAM_ERROR_FAILED_LOGOFF:
        return "Unknown logoff failure";
    case STEAM_ERROR_FAILED_LOGON:
        return "Unknown logon failure";
    case STEAM_ERROR_FAILED_MESSAGE_SEND:
        return "Failed to send message";
    case STEAM_ERROR_FAILED_POLL:
        return "Failed to poll server";
    case STEAM_ERROR_INVALID_AUTH_CODE:
        return "Invalid SteamGuard authentication code";
    case STEAM_ERROR_INVALID_LOGON:
        return "Invalid login details";
    case STEAM_ERROR_PARSE_JSON:
        return "Failed to parse JSON reply";
    case STEAM_ERROR_REQ_AUTH_CODE:
        return "SteamGuard authentication code required";
    case STEAM_ERROR_MISMATCH_UMQID:
        return "Mismatch in UMQIDs";
    }
    
    return "";
}

gchar *steam_message_type_str(SteamMessageType type)
{
    switch(type) {
    case STEAM_MESSAGE_TYPE_SAYTEXT:
        return "saytext";
    case STEAM_MESSAGE_TYPE_EMOTE:
        return "emote";
    }
    
    return "";
}

gchar *steam_persona_state_str(SteamPersonaState state)
{
    switch(state) {
    case STEAM_PERSONA_STATE_OFFLINE:
        return "Offline";
    case STEAM_PERSONA_STATE_ONLINE:
        return "Online";
    case STEAM_PERSONA_STATE_BUSY:
        return "Busy";
    case STEAM_PERSONA_STATE_AWAY:
        return "Away";
    case STEAM_PERSONA_STATE_SNOOZE:
        return "Snooze";
    }
    
    return "";
}
