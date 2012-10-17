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

#include <glib-object.h>

#include <bitlbee.h>
#include <http_client.h>

#include "steam-api.h"
#include "xmltree.h"


#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
    g_slist_foreach(list, (GFunc) free_func, NULL);
    g_slist_free(list);
}
#endif


#define steam_api_func(p, e) G_STMT_START{                       \
    if(p->func != NULL)                                          \
        (((SteamAPIFunc) p->func) (p->api, e, p->data));         \
}G_STMT_END

#define steam_list_func(p, l, e) G_STMT_START{                   \
    if(p->func != NULL)                                          \
        (((SteamListFunc) p->func) (p->api, l, e, p->data));     \
}G_STMT_END

#define steam_user_info_func(p, i, e) G_STMT_START{              \
    if(p->func != NULL)                                          \
        (((SteamUserInfoFunc) p->func) (p->api, i, e, p->data)); \
}G_STMT_END


typedef enum   _SteamPairType SteamPairType;
typedef struct _SteamPair     SteamPair;
typedef struct _SteamFuncPair SteamFuncPair;

enum _SteamPairType
{
    STEAM_PAIR_AUTH,
    STEAM_PAIR_FRIENDS,
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
    SteamAPI      *api;
    SteamPairType  type;

    gpointer func;
    gpointer data;

    struct http_request *req;
};

static SteamFuncPair *steam_pair_new(SteamPairType type, SteamAPI *api,
                                     gpointer func, gpointer data)
{
    SteamFuncPair *fp;

    fp = g_new0(SteamFuncPair, 1);

    fp->api  = api;
    fp->type = type;
    fp->func = func;
    fp->data = data;

    return fp;
}

static gboolean steam_xt_node_get(struct xt_node *xr, const gchar *name,
                                  struct xt_node **xn)
{
    *xn = xt_find_node(xr->children, name);
    return (*xn != NULL);
}

SteamAPI *steam_api_new(const gchar *umqid)
{
    SteamAPI *api;
    GRand    *rand;

    api = g_new0(SteamAPI, 1);

    if(umqid == NULL) {
        rand       = g_rand_new();
        api->umqid = g_strdup_printf("%u", g_rand_int(rand));

        g_rand_free(rand);
    } else {
        api->umqid = g_strdup(umqid);
    }

    return api;
}

static void steam_api_cb_null(struct http_request *req)
{
    /* Fake callback for http_request */
}

void steam_api_free_cs(SteamAPI *api)
{
    struct http_request *req;
    GSList *l;

    g_return_if_fail(api != NULL);

    /* Set a fake callback for each http_request that is still active.
     * This allows the request to be correctly cleaned up after, but
     * stops steam-api from handling the request with invalid pointers.
     */
    for(l = api->reqs; l != NULL; l = l->next) {
        req = l->data;

        req->func = steam_api_cb_null;
        req->data = NULL;
    }

    g_slist_free(api->reqs);
    api->reqs = NULL;
}

void steam_api_free(SteamAPI *api)
{
    g_return_if_fail(api != NULL);

    g_slist_free_full(api->friends, g_free);
    steam_api_free_cs(api);

    g_free(api->token);
    g_free(api->steamid);
    g_free(api->umqid);
    g_free(api->lmid);

    g_free(api);
}

static void steam_api_auth_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if(steam_xt_node_get(xr, "access_token", &xn)) {
        g_free(fp->api->token);
        fp->api->token = g_strdup(xn->text);

        steam_api_func(fp, STEAM_ERROR_SUCCESS);
    } else if(steam_xt_node_get(xr, "x_errorcode", &xn)) {
        if(!g_strcmp0("incorrect_login", xn->text))
            steam_api_func(fp, STEAM_ERROR_INVALID_LOGON);
        else if(!g_strcmp0("invalid_steamguard_code", xn->text))
            steam_api_func(fp, STEAM_ERROR_INVALID_AUTH_CODE);
        else if(!g_strcmp0("steamguard_code_required", xn->text))
            steam_api_func(fp, STEAM_ERROR_REQ_AUTH_CODE);
        else
            steam_api_func(fp, STEAM_ERROR_FAILED_AUTH);
    } else {
        steam_api_func(fp, STEAM_ERROR_FAILED_AUTH);
    }
}

static void steam_api_friends_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;

    g_slist_free_full(fp->api->friends, g_free);
    fp->api->friends = NULL;

    if(!steam_xt_node_get(xr, "friends", &xn)) {
        steam_list_func(fp, fp->api->friends, STEAM_ERROR_SUCCESS);
        return;
    }

    if(xn->children == NULL) {
        steam_list_func(fp, fp->api->friends, STEAM_ERROR_SUCCESS);
        return;
    }

    for(xn = xn->children; xn != NULL; xn = xn->next) {
        if(!steam_xt_node_get(xn, "relationship", &xe))
            continue;

        if(g_strcmp0(xe->text, "friend"))
            continue;

        if(!steam_xt_node_get(xn, "steamid", &xe))
            continue;

        fp->api->friends = g_slist_append(fp->api->friends,
                                          g_strdup(xe->text));
    }

    steam_list_func(fp, fp->api->friends, STEAM_ERROR_SUCCESS);
}

static void steam_api_logon_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if(!steam_xt_node_get(xr, "umqid", &xn)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_UMQID);
        return;
    }

    if(g_strcmp0(fp->api->umqid, xn->text)) {
        steam_api_func(fp, STEAM_ERROR_MISMATCH_UMQID);
        return;
    }

    if(!steam_xt_node_get(xr, "steamid", &xn)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_STEAMID);
        return;
    }

    g_free(fp->api->steamid);
    fp->api->steamid = g_strdup(xn->text);

    if(!steam_xt_node_get(xr, "message", &xn)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_MESSAGE);
        return;
    }

    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(xn->text);

    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_logoff_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if(!steam_xt_node_get(xr, "error", &xn)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_LOGOFF);
        return;
    }

    if(g_strcmp0("OK", xn->text)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_LOGOFF);
        return;
    }

    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_message_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if(!steam_xt_node_get(xr, "error", &xn)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }

    if(g_strcmp0("OK", xn->text)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }

    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_poll_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    SteamMessage   *sm;

    GSList *mu = NULL;

    if(!steam_xt_node_get(xr, "messagelast", &xn)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    if(!g_strcmp0(fp->api->lmid, xn->text)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(xn->text);

    if(!steam_xt_node_get(xr, "messages", &xn)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    if(xn->children == NULL) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    for(xn = xn->children; xn != NULL; xn = xn->next) {
        if(!steam_xt_node_get(xn, "steamid_from", &xe))
            continue;

        if(!g_strcmp0(fp->api->steamid, xe->text))
            continue;

        sm = g_new0(SteamMessage, 1);
        sm->steamid = xe->text;

        if(!steam_xt_node_get(xn, "type", &xe)) {
            g_free(sm);
            continue;
        }

        if(!g_strcmp0("emote", xe->text)) {
            if(!steam_xt_node_get(xn, "text", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type = STEAM_MESSAGE_TYPE_EMOTE;
            sm->text = xe->text;
        } else if(!g_strcmp0("leftconversation", xe->text)) {
            sm->type = STEAM_MESSAGE_TYPE_LEFT_CONV;
        } else if(!g_strcmp0("saytext", xe->text)) {
            if(!steam_xt_node_get(xn, "text", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type = STEAM_MESSAGE_TYPE_SAYTEXT;
            sm->text = xe->text;
        } else if(!g_strcmp0("typing", xe->text)) {
            sm->type = STEAM_MESSAGE_TYPE_TYPING;
        } else if(!g_strcmp0("personastate", xe->text)) {
            if(!steam_xt_node_get(xn, "persona_name", &xe)) {
                g_free(sm);
                continue;
            }

            sm->name = xe->text;

            if(!steam_xt_node_get(xn, "persona_state", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type  = STEAM_MESSAGE_TYPE_STATE;
            sm->state = g_ascii_strtoll(xe->text, NULL, 10);
        } else {
            g_free(sm);
            continue;
        }

        mu = g_slist_append(mu, sm);
    }

    steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
    g_slist_free_full(mu, g_free);
}

static void steam_api_user_info_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    SteamUserInfo   info;

    if(!steam_xt_node_get(xr, "players", &xn)) {
        steam_user_info_func(fp, NULL, STEAM_ERROR_EMPTY_USER_INFO);
        return;
    }

    xn = xn->children;

    if(xn == NULL) {
        steam_user_info_func(fp, NULL, STEAM_ERROR_EMPTY_USER_INFO);
        return;
    }

    memset(&info, 0, sizeof (SteamUserInfo));

    if(steam_xt_node_get(xn, "steamid", &xe))
        info.steamid  = xe->text;

    if(steam_xt_node_get(xn, "personastate", &xe))
        info.state    = g_ascii_strtoll(xe->text, NULL, 10);

    if(steam_xt_node_get(xn, "personaname", &xe))
        info.name     = xe->text;

    if(steam_xt_node_get(xn, "realname", &xe))
        info.realname = xe->text;

    if(steam_xt_node_get(xn, "profileurl", &xe))
        info.profile  = xe->text;

    steam_user_info_func(fp, &info, STEAM_ERROR_SUCCESS);
}

static void steam_api_cb_error(SteamFuncPair *fp, SteamError err)
{
    switch(fp->type) {
    case STEAM_PAIR_AUTH:
    case STEAM_PAIR_LOGON:
    case STEAM_PAIR_LOGOFF:
    case STEAM_PAIR_MESSAGE:
        steam_api_func(fp, err);
        break;

    case STEAM_PAIR_FRIENDS:
    case STEAM_PAIR_POLL:
        steam_list_func(fp, NULL, err);
        break;

    case STEAM_PAIR_USER_INFO:
        steam_user_info_func(fp, NULL, err);
        break;
    }

    g_free(fp);
}

static void steam_api_cb(struct http_request *req)
{
    SteamFuncPair    *fp = req->data;
    struct xt_parser *xt;
    SteamError        err;

    fp->api->reqs = g_slist_remove(fp->api->reqs, fp->req);

    if((req->status_code != 200) || (req->body_size < 1)) {
        if(req->status_code == 401)
            err = STEAM_ERROR_NOT_AUTHORIZED;
        else
            err = STEAM_ERROR_EMPTY_XML;

        steam_api_cb_error(fp, err);
        return;
    }

    xt = xt_new(NULL, NULL);

    if(xt_feed(xt, req->reply_body, req->body_size) < 0) {
        steam_api_cb_error(fp, STEAM_ERROR_PARSE_XML);
        xt_free(xt);
        return;
    }

    switch(fp->type) {
    case STEAM_PAIR_AUTH:
        steam_api_auth_cb(fp, xt->root);
        break;

    case STEAM_PAIR_FRIENDS:
        steam_api_friends_cb(fp, xt->root);
        break;

    case STEAM_PAIR_LOGON:
        steam_api_logon_cb(fp, xt->root);
        break;

    case STEAM_PAIR_LOGOFF:
        steam_api_logoff_cb(fp, xt->root);
        break;

    case STEAM_PAIR_MESSAGE:
        steam_api_message_cb(fp, xt->root);
        break;

    case STEAM_PAIR_POLL:
        steam_api_poll_cb(fp, xt->root);
        break;

    case STEAM_PAIR_USER_INFO:
        steam_api_user_info_cb(fp, xt->root);
        break;
    }

    xt_free(xt);
    g_free(fp);
}

static void steam_api_req(const gchar *path, SteamPair *params, gint psize,
                          gboolean ssl, gboolean post, SteamFuncPair *fp)
{
    gchar **sp,  *esc;
    gchar  *req, *rd;

    gsize len;
    guint i;

    sp = g_new0(gchar*, (psize + 2));

    for(i = 0; i < psize; i++) {
        if(params[i].value == NULL)
            params[i].value = "";

        esc   = g_uri_escape_string(params[i].value, NULL, FALSE);
        sp[i] = g_strdup_printf("%s=%s", params[i].key, esc);

        g_free(esc);
    }

    sp[psize] = g_strdup("format=xml");

    rd  = g_strjoinv("&", sp);
    len = strlen(rd);

    g_strfreev(sp);

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

    fp->req = http_dorequest(STEAM_API_HOST, (ssl ? 443 : 80), ssl, req,
                             steam_api_cb, fp);

    fp->api->reqs = g_slist_append(fp->api->reqs, fp->req);

    g_free(rd);
    g_free(req);
}

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    const gchar *user, const gchar *pass,
                    SteamAPIFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);

    SteamPair ps[7] = {
        {"client_id",       "DE45CD61"},
        {"grant_type",      "password"},
        {"username",        user},
        {"password",        pass},
        {"x_emailauthcode", authcode},
        {"x_webcookie",     ""},
        {"scope",           "read_profile write_profile "
                            "read_client write_client"}
    };

    steam_api_req(STEAM_PATH_AUTH, ps, 7, TRUE, TRUE,
                  steam_pair_new(STEAM_PAIR_AUTH, api, func, data));
}

void steam_api_friends(SteamAPI *api, SteamListFunc func, gpointer data)
{
    g_return_if_fail(api != NULL);

    SteamPair ps[3] = {
        {"access_token", api->token},
        {"steamid",      api->steamid},
        {"relationship", "friend"}
    };

    steam_api_req(STEAM_PATH_FRIENDS, ps, 3, TRUE, FALSE,
                  steam_pair_new(STEAM_PAIR_FRIENDS, api, func, data));
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

void steam_api_poll(SteamAPI *api, SteamListFunc func, gpointer data)
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
    case STEAM_ERROR_EMPTY_MESSAGE:
        return "Empty message";
    case STEAM_ERROR_EMPTY_STEAMID:
        return "Empty SteamID";
    case STEAM_ERROR_EMPTY_UMQID:
        return "Empty UMQID";
    case STEAM_ERROR_EMPTY_USER_INFO:
        return "Empty user information";
    case STEAM_ERROR_EMPTY_XML:
        return "Failed to receive XML reply";
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
    case STEAM_ERROR_MISMATCH_UMQID:
        return "Mismatch in UMQIDs";
    case STEAM_ERROR_NOT_AUTHORIZED:
        return "Not Authorized";
    case STEAM_ERROR_PARSE_XML:
        return "Failed to parse XML reply";
    case STEAM_ERROR_REQ_AUTH_CODE:
        return "SteamGuard authentication code required";
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
    case STEAM_MESSAGE_TYPE_LEFT_CONV:
        return "leftconversation";
    case STEAM_MESSAGE_TYPE_STATE:
        return "personastate";
    case STEAM_MESSAGE_TYPE_TYPING:
        return "typing";
    }

    return "";
}

gchar *steam_state_str(SteamState state)
{
    switch(state) {
    case STEAM_STATE_OFFLINE:
        return "Offline";
    case STEAM_STATE_ONLINE:
        return "Online";
    case STEAM_STATE_BUSY:
        return "Busy";
    case STEAM_STATE_AWAY:
        return "Away";
    case STEAM_STATE_SNOOZE:
        return "Snooze";
    }

    return "";
}
