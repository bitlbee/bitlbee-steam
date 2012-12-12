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

#include <string.h>

#include "steam-api.h"
#include "steam-http.h"
#include "steam-util.h"

#define steam_api_func(p, e) G_STMT_START {                  \
    if (p->func != NULL)                                     \
        (((SteamAPIFunc) p->func) (p->api, e, p->data));     \
} G_STMT_END

#define steam_list_func(p, l, e) G_STMT_START {              \
    if (p->func != NULL)                                     \
        (((SteamListFunc) p->func) (p->api, l, e, p->data)); \
} G_STMT_END

typedef enum   _SteamPairType SteamPairType;
typedef struct _SteamFuncPair SteamFuncPair;

typedef void (*SteamParseFunc) (SteamFuncPair *fp, struct xt_node *xr);

enum _SteamPairType
{
    STEAM_PAIR_AUTH = 0,
    STEAM_PAIR_FRIENDS,
    STEAM_PAIR_LOGON,
    STEAM_PAIR_LOGOFF,
    STEAM_PAIR_MESSAGE,
    STEAM_PAIR_POLL,
    STEAM_PAIR_SUMMARIES,

    STEAM_PAIR_LAST
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

SteamAPI *steam_api_new(const gchar *umqid)
{
    SteamAPI *api;
    GRand    *rand;

    api = g_new0(SteamAPI, 1);

    if (umqid == NULL) {
        rand       = g_rand_new();
        api->umqid = g_strdup_printf("%u", g_rand_int(rand));

        g_rand_free(rand);
    } else {
        api->umqid = g_strdup(umqid);
    }

    api->http = steam_http_new(STEAM_API_AGENT);

    return api;
}

void steam_api_free(SteamAPI *api)
{
    g_return_if_fail(api != NULL);

    steam_http_free(api->http);

    g_free(api->token);
    g_free(api->steamid);
    g_free(api->umqid);
    g_free(api->lmid);
    g_free(api);
}

static void steam_api_auth_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if (steam_util_xt_node(xr, "access_token", &xn)) {
        g_free(fp->api->token);
        fp->api->token = g_strdup(xn->text);

        steam_api_func(fp, STEAM_ERROR_SUCCESS);
    } else if (steam_util_xt_node(xr, "x_errorcode", &xn)) {
        if (!g_strcmp0("incorrect_login", xn->text))
            steam_api_func(fp, STEAM_ERROR_INVALID_LOGON);
        else if (!g_strcmp0("invalid_steamguard_code", xn->text))
            steam_api_func(fp, STEAM_ERROR_INVALID_AUTH_CODE);
        else if (!g_strcmp0("steamguard_code_required", xn->text))
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
    GSList         *fl;
    SteamError      err;

    fl = NULL;

    if (!steam_util_xt_node(xr, "friends", &xn)) {
        steam_list_func(fp, fl, STEAM_ERROR_EMPTY_FRIENDS);
        return;
    }

    if (xn->children == NULL) {
        steam_list_func(fp, fl, STEAM_ERROR_EMPTY_FRIENDS);
        return;
    }

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xt_node(xn, "relationship", &xe))
            continue;

        if (g_strcmp0(xe->text, "friend"))
            continue;

        if (!steam_util_xt_node(xn, "steamid", &xe))
            continue;

        fl = g_slist_prepend(fl, xe->text);
    }

    err = (fl != NULL) ? STEAM_ERROR_SUCCESS : STEAM_ERROR_EMPTY_FRIENDS;

    steam_list_func(fp, fl, err);
    g_slist_free(fl);
}

static void steam_api_logon_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if (!steam_util_xt_node(xr, "umqid", &xn)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_UMQID);
        return;
    }

    if (g_strcmp0(fp->api->umqid, xn->text)) {
        steam_api_func(fp, STEAM_ERROR_MISMATCH_UMQID);
        return;
    }

    if (!steam_util_xt_node(xr, "steamid", &xn)) {
        steam_api_func(fp, STEAM_ERROR_EMPTY_STEAMID);
        return;
    }

    g_free(fp->api->steamid);
    fp->api->steamid = g_strdup(xn->text);

    if (!steam_util_xt_node(xr, "message", &xn)) {
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

    if (!steam_util_xt_node(xr, "error", &xn)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_LOGOFF);
        return;
    }

    if (g_strcmp0("OK", xn->text)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_LOGOFF);
        return;
    }

    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_message_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn;

    if (!steam_util_xt_node(xr, "error", &xn)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }

    if (g_strcmp0("OK", xn->text)) {
        steam_api_func(fp, STEAM_ERROR_FAILED_MESSAGE_SEND);
        return;
    }

    steam_api_func(fp, STEAM_ERROR_SUCCESS);
}

static void steam_api_poll_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    SteamMessage   *sm;
    GSList         *mu;

    mu = NULL;

    if (!steam_util_xt_node(xr, "messagelast", &xn)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    if (!g_strcmp0(fp->api->lmid, xn->text)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    g_free(fp->api->lmid);
    fp->api->lmid = g_strdup(xn->text);

    if (!steam_util_xt_node(xr, "messages", &xn)) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    if (xn->children == NULL) {
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
        return;
    }

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xt_node(xn, "steamid_from", &xe))
            continue;

        if (!g_strcmp0(fp->api->steamid, xe->text))
            continue;

        sm = g_new0(SteamMessage, 1);
        sm->steamid = xe->text;

        if (!steam_util_xt_node(xn, "type", &xe)) {
            g_free(sm);
            continue;
        }

        if (!g_strcmp0("emote", xe->text)) {
            if (!steam_util_xt_node(xn, "text", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type = STEAM_MESSAGE_TYPE_EMOTE;
            sm->text = xe->text;
        } else if (!g_strcmp0("leftconversation", xe->text)) {
            sm->type = STEAM_MESSAGE_TYPE_LEFT_CONV;
        } else if (!g_strcmp0("saytext", xe->text)) {
            if (!steam_util_xt_node(xn, "text", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type = STEAM_MESSAGE_TYPE_SAYTEXT;
            sm->text = xe->text;
        } else if (!g_strcmp0("typing", xe->text)) {
            sm->type = STEAM_MESSAGE_TYPE_TYPING;
        } else if (!g_strcmp0("personastate", xe->text)) {
            if (!steam_util_xt_node(xn, "persona_name", &xe)) {
                g_free(sm);
                continue;
            }

            sm->name = xe->text;

            if (!steam_util_xt_node(xn, "persona_state", &xe)) {
                g_free(sm);
                continue;
            }

            sm->type  = STEAM_MESSAGE_TYPE_STATE;
            sm->state = g_ascii_strtoll(xe->text, NULL, 10);
        } else {
            g_free(sm);
            continue;
        }

        mu = g_slist_prepend(mu, sm);
    }

    steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
    g_slist_free_full(mu, g_free);
}

static void steam_api_summaries_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    GSList         *mu;
    SteamSummary   *ss;
    SteamError      err;

    mu = NULL;

    if (!steam_util_xt_node(xr, "players", &xn)) {
        steam_list_func(fp, NULL, STEAM_ERROR_EMPTY_SUMMARY);
        return;
    }

    if (xn->children == NULL) {
        steam_list_func(fp, mu, STEAM_ERROR_EMPTY_SUMMARY);
        return;
    }

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xt_node(xn, "steamid", &xe))
            continue;

        ss = g_new0(SteamSummary, 1);
        ss->steamid = xe->text;

        if (steam_util_xt_node(xn, "gameextrainfo", &xe))
            ss->game = xe->text;

        if (steam_util_xt_node(xn, "gameserverip", &xe))
            ss->server = xe->text;

        if (steam_util_xt_node(xn, "personaname", &xe))
            ss->name = xe->text;

        if (steam_util_xt_node(xn, "personastate", &xe))
            ss->state = g_ascii_strtoll(xe->text, NULL, 10);

        if (steam_util_xt_node(xn, "profileurl", &xe))
            ss->profile = xe->text;

        if (steam_util_xt_node(xn, "realname", &xe))
            ss->realname = xe->text;

        mu = g_slist_prepend(mu, ss);
    }

    err = (mu != NULL) ? STEAM_ERROR_SUCCESS : STEAM_ERROR_EMPTY_SUMMARY;
    steam_list_func(fp, mu, err);
}

static void steam_api_cb_error(SteamFuncPair *fp, SteamError err)
{
    switch (fp->type) {
    case STEAM_PAIR_AUTH:
    case STEAM_PAIR_LOGON:
    case STEAM_PAIR_LOGOFF:
    case STEAM_PAIR_MESSAGE:
        steam_api_func(fp, err);
        break;

    case STEAM_PAIR_FRIENDS:
    case STEAM_PAIR_POLL:
    case STEAM_PAIR_SUMMARIES:
        steam_list_func(fp, NULL, err);
        break;
    }

    g_free(fp);
}

static gboolean steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamFuncPair    *fp = data;
    struct xt_parser *xt;

    if ((fp->type < 0) || (fp->type > STEAM_PAIR_LAST)) {
        g_free(fp);
        return TRUE;
    }

    if (req->body_size < 1) {
        steam_api_cb_error(fp, STEAM_ERROR_HTTP_EMPTY);
        return TRUE;
    }

    if (req->errcode != 200) {
        steam_api_cb_error(fp, STEAM_ERROR_HTTP_GENERIC);
        return TRUE;
    }

    xt = xt_new(NULL, NULL);

    if (xt_feed(xt, req->body, req->body_size) < 0) {
        if (global.conf->verbose && (xt->gerr != NULL)) {
            g_print("  ** Markup parser error (%d): %s **\n\n",
                    xt->gerr->code, xt->gerr->message);
        }

        steam_api_cb_error(fp, STEAM_ERROR_PARSE_XML);
        xt_free(xt);
        return TRUE;
    }

    SteamParseFunc pf[STEAM_PAIR_LAST];

    pf[STEAM_PAIR_AUTH]      = steam_api_auth_cb;
    pf[STEAM_PAIR_FRIENDS]   = steam_api_friends_cb;
    pf[STEAM_PAIR_LOGON]     = steam_api_logon_cb;
    pf[STEAM_PAIR_LOGOFF]    = steam_api_logoff_cb;
    pf[STEAM_PAIR_MESSAGE]   = steam_api_message_cb;
    pf[STEAM_PAIR_POLL]      = steam_api_poll_cb;
    pf[STEAM_PAIR_SUMMARIES] = steam_api_summaries_cb;

    pf[fp->type](fp, xt->root);

    xt_free(xt);
    g_free(fp);

    return TRUE;
}

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    const gchar *user, const gchar *pass,
                    SteamAPIFunc func, gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);

    fp  = steam_pair_new(STEAM_PAIR_AUTH, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_AUTH, steam_api_cb, fp);

    steam_http_req_params_set(req, 8,
        "format",          "xml",
        "client_id",       "DE45CD61",
        "grant_type",      "password",
        "username",        user,
        "password",        pass,
        "x_emailauthcode", authcode,
        "x_webcookie",     NULL,
        "scope", "read_profile write_profile read_client write_client"
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_friends(SteamAPI *api, SteamListFunc func, gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);

    fp  = steam_pair_new(STEAM_PAIR_FRIENDS, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_FRIENDS, steam_api_cb, fp);

    steam_http_req_params_set(req, 4,
        "format",       "xml",
        "access_token", api->token,
        "steamid",      api->steamid,
        "relationship", "friend"
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logon(SteamAPI *api, SteamAPIFunc func, gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);

    fp  = steam_pair_new(STEAM_PAIR_LOGON, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_LOGON, steam_api_cb, fp);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logoff(SteamAPI *api, SteamAPIFunc func, gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);

    fp  = steam_pair_new(STEAM_PAIR_LOGOFF, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_LOGOFF, steam_api_cb, fp);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_message(SteamAPI *api, SteamMessage *sm, SteamAPIFunc func,
                       gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);
    g_return_if_fail(sm  != NULL);

    fp  = steam_pair_new(STEAM_PAIR_MESSAGE, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_MESSAGE, steam_api_cb, fp);

    steam_http_req_params_set(req, 5,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid,
        "steamid_dst",  sm->steamid,
        "type",         steam_message_type_str(sm->type)
    );

    switch (sm->type) {
    case STEAM_MESSAGE_TYPE_SAYTEXT:
    case STEAM_MESSAGE_TYPE_EMOTE:
        steam_http_req_params_set(req, 1, "text", sm->text);
        break;

    case STEAM_MESSAGE_TYPE_TYPING:
        break;

    default:
        return;
    }

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_poll(SteamAPI *api, SteamListFunc func, gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api != NULL);

    fp  = steam_pair_new(STEAM_PAIR_POLL, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_POLL, steam_api_cb, fp);

    steam_http_req_headers_set(req, 1, "Connection", "Keep-Alive");

    steam_http_req_params_set(req, 5,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid,
        "message",      api->lmid,
        "sectimeout",   STEAM_API_KEEP_ALIVE
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_summaries(SteamAPI *api, GSList *friends, SteamListFunc func,
                         gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    GSList *s;
    GSList *e;
    GSList *l;

    gsize  size;
    gint   i;

    gchar *str;
    gchar *p;

    g_return_if_fail(api != NULL);

    if (friends == NULL) {
        if (func != NULL)
            func(api, NULL, STEAM_ERROR_SUCCESS, data);

        return;
    }

    s  = friends;
    fp = steam_pair_new(STEAM_PAIR_SUMMARIES, api, func, data);

    while (TRUE) {
        size = 0;

        for (l = s, i = 0; (l != NULL) && (i < 100); l = l->next, i++)
            size += strlen(l->data) + 1;

        str = g_new0(gchar, size);
        p   = g_stpcpy(str, s->data);
        e   = l;

        for (l = s->next; l != e; l = l->next) {
            p = g_stpcpy(p, ",");
            p = g_stpcpy(p, l->data);
        }

        req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                                 STEAM_PATH_SUMMARIES, steam_api_cb, fp);

        steam_http_req_params_set(req, 3,
            "format",       "xml",
            "access_token", api->token,
            "steamids",     str
        );

        g_free(str);

        req->flags = STEAM_HTTP_FLAG_SSL;
        steam_http_req_send(req);

        if (e != NULL)
            s = e->next;
        else
            break;
    }
}

void steam_api_summary(SteamAPI *api, const gchar *steamid, SteamListFunc func,
                       gpointer data)
{
    SteamHttpReq  *req;
    SteamFuncPair *fp;

    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);

    fp  = steam_pair_new(STEAM_PAIR_SUMMARIES, api, func, data);
    req = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                             STEAM_PATH_SUMMARIES, steam_api_cb, fp);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "steamids",     steamid
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

gchar *steam_api_error_str(SteamError err)
{
    gchar *strs[STEAM_ERROR_LAST];

    if ((err < 0) || (err > STEAM_ERROR_LAST))
        return "";

    strs[STEAM_ERROR_SUCCESS]             = "Success";

    strs[STEAM_ERROR_EMPTY_FRIENDS]       = "Empty friends list";
    strs[STEAM_ERROR_EMPTY_MESSAGE]       = "Empty message";
    strs[STEAM_ERROR_EMPTY_STEAMID]       = "Empty SteamID";
    strs[STEAM_ERROR_EMPTY_SUMMARY]       = "Empty summary "
                                            "information returned";
    strs[STEAM_ERROR_EMPTY_UMQID]         = "Empty UMQID";

    strs[STEAM_ERROR_FAILED_AUTH]         = "Authentication failed";
    strs[STEAM_ERROR_FAILED_LOGOFF]       = "Unknown logoff failure";
    strs[STEAM_ERROR_FAILED_LOGON]        = "Unknown logon failure";
    strs[STEAM_ERROR_FAILED_MESSAGE_SEND] = "Failed to send message";
    strs[STEAM_ERROR_FAILED_POLL]         = "Failed to poll server";

    strs[STEAM_ERROR_HTTP_EMPTY]          = "Empty HTTP reply returned";
    strs[STEAM_ERROR_HTTP_GENERIC]        = "Generic HTTP error returned";

    strs[STEAM_ERROR_INVALID_AUTH_CODE]   = "Invalid SteamGuard "
                                            "authentication code";
    strs[STEAM_ERROR_INVALID_LOGON]       = "Invalid login details";

    strs[STEAM_ERROR_MISMATCH_UMQID]      = "Mismatch in UMQIDs";
    strs[STEAM_ERROR_PARSE_XML]           = "Failed to parse XML reply";
    strs[STEAM_ERROR_REQ_AUTH_CODE]       = "SteamGuard authentication "
                                            "code required";

    return strs[err];
}

gchar *steam_message_type_str(SteamMessageType type)
{
    gchar *strs[STEAM_MESSAGE_TYPE_LAST];

    if ((type < 0) || (type > STEAM_MESSAGE_TYPE_LAST))
        return "";

    strs[STEAM_MESSAGE_TYPE_SAYTEXT]   = "saytext";
    strs[STEAM_MESSAGE_TYPE_EMOTE]     = "emote";
    strs[STEAM_MESSAGE_TYPE_LEFT_CONV] = "leftconversation";
    strs[STEAM_MESSAGE_TYPE_STATE]     = "personastate";
    strs[STEAM_MESSAGE_TYPE_TYPING]    = "typing";

    return strs[type];
}

gchar *steam_state_str(SteamState state)
{
    gchar *strs[STEAM_STATE_LAST];

    if ((state < 0) || (state > STEAM_STATE_LAST))
        return "";

    strs[STEAM_STATE_OFFLINE] = "Offline";
    strs[STEAM_STATE_ONLINE]  = "Online";
    strs[STEAM_STATE_BUSY]    = "Busy";
    strs[STEAM_STATE_AWAY]    = "Away";
    strs[STEAM_STATE_SNOOZE]  = "Snooze";

    return strs[state];
}

SteamState steam_state_from_str(const gchar *state)
{
    gchar *s;
    guint  i;

    if (state == NULL)
        return STEAM_STATE_OFFLINE;

    for (i = 0; i < STEAM_STATE_LAST; i++) {
        s = steam_state_str(i);

        if (!g_ascii_strcasecmp(state, s))
            return i;
    }

    return STEAM_STATE_OFFLINE;
}
