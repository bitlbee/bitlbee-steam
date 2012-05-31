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

#define steam_api_func(p, e) (p->func(p->api, e, p->data))

typedef enum   _SteamPairType SteamPairType;
typedef struct _SteamPair     SteamPair;
typedef struct _SteamFuncPair SteamFuncPair;

enum _SteamPairType
{
    STEAM_PAIR_AUTH,
    STEAM_PAIR_LOGON,
    STEAM_PAIR_LOGOFF,
    STEAM_PAIR_POLL
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
    
    SteamAPIFunc func;
    gpointer data;
};

static SteamFuncPair *steam_pair_new(SteamPairType type, SteamAPI *api,
                                     SteamAPIFunc func, gpointer data)
{
    SteamFuncPair *fp;
    
    fp = g_new0(SteamFuncPair, 1);
    fp->type = type;
    fp->api  = api;
    fp->func = func;
    fp->data = data;
    
    return fp;
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
    case STEAM_ERROR_FAILED_AUTH:
        return "Authentication failed";
    case STEAM_ERROR_FAILED_LOGOFF:
        return "Unknown logoff failure";
    case STEAM_ERROR_FAILED_LOGON:
        return "Unknown logon failure";
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

static void steam_api_friends_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_logon_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so;
    const gchar *sm;
    
    g_return_if_fail(fp != NULL);
    g_return_if_fail(fp->data != NULL);
    
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

static void steam_api_poll_cb(SteamFuncPair *fp, json_object *jo)
{
    json_object *so, *se, *sv;
    const gchar *sm;
    gint len, si, i;
    
    if(!json_object_object_get_ex(jo, "messagelast", &so)) {
        steam_api_func(fp, STEAM_ERROR_SUCCESS);
        return;
    }
    
    sm = json_object_get_string(so);
    
    if(!g_strcmp0(fp->api->lmid, sm)) {
        steam_api_func(fp, STEAM_ERROR_SUCCESS);
        return;
    }
    
    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(sm);
    
    if(!json_object_object_get_ex(jo, "messages", &so)) {
        steam_api_func(fp, STEAM_ERROR_SUCCESS);
        return;
    }
    
    if(json_object_get_type(so) != json_type_array) {
        steam_api_func(fp, STEAM_ERROR_SUCCESS);
        return;
    }
    
    len = json_object_array_length(so);
    
    for(i = 0; i < len; i++) {
        se = json_object_array_get_idx(so, i);
        
        if(!json_object_object_get_ex(se, "type", &sv))
            continue;
        
        sm = json_object_get_string(sv);
        
        if(!g_strcmp0("my_saytext", sm)) {
            if(!json_object_object_get_ex(se, "persona_name", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            
            g_print("New message, id: %s\n", sm);
        } else if(!g_strcmp0("personastate", sm)) {
            if(!json_object_object_get_ex(se, "steamid_from", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            
            if(!g_strcmp0(fp->api->steamid, sm))
                continue;
            
            if(!json_object_object_get_ex(se, "persona_name", &sv))
                continue;
            
            sm = json_object_get_string(sv);
            
            if(!json_object_object_get_ex(se, "persona_state", &sv))
                continue;
            
            si = json_object_get_int(sv);
            
            g_print("Persona state change(%d): %s\n", si, sm);
        }
    }
    
    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_cb(struct http_request *req)
{
    SteamFuncPair *fp = req->data;
    json_tokener *jt;
    json_object  *jo;
    
    g_return_if_fail(fp != NULL);
    
    if((req->status_code != 200) || (req->reply_body == NULL)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_JSON);
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
    
    case STEAM_PAIR_POLL:
        steam_api_poll_cb(fp, jo);
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
            
            //esc   = g_uri_escape_string(params[i].value, NULL, FALSE);
            esc   = g_strdup(params[i].value);
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

void steam_api_poll(SteamAPI *api, SteamAPIFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);
    
    SteamPair ps[3] = {
        {"steamid", api->steamid},
        {"umqid",   api->umqid},
        {"message", api->lmid}
    };
    
    steam_api_req(STEAM_PATH_POLL, ps, 3, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_POLL, api, func, data));
}
