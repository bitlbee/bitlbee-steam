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

typedef enum   _SteamApiType SteamApiType;
typedef struct _SteamApiPriv SteamApiPriv;

typedef SteamError (*SteamParseFunc) (SteamApiPriv *priv, struct xt_node *xr);

enum _SteamApiType
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

struct _SteamApiPriv
{
    SteamAPI     *api;
    SteamApiType  type;
    SteamError    err;

    gpointer func;
    gpointer data;

    gpointer       rdata;
    GDestroyNotify rfunc;
};


static SteamApiPriv *steam_api_priv_new(SteamApiType type, SteamAPI *api,
                                        gpointer func, gpointer data)
{
    SteamApiPriv *priv;

    priv = g_new0(SteamApiPriv, 1);

    priv->api  = api;
    priv->type = type;
    priv->err  = STEAM_ERROR_SUCCESS;
    priv->func = func;
    priv->data = data;

    return priv;
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

    api->http = steam_http_new(STEAM_API_AGENT, g_free);

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

static void steam_slist_free_full(GSList *list)
{
    g_slist_free_full(list, g_free);
}

static SteamError steam_api_auth_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;

    if (steam_util_xt_node(xr, "access_token", &xn)) {
        g_free(priv->api->token);
        priv->api->token = g_strdup(xn->text);
        return STEAM_ERROR_SUCCESS;
    }

    if (!steam_util_xt_node(xr, "x_errorcode", &xn))
        return STEAM_ERROR_FAILED_AUTH;

    if (!g_strcmp0("incorrect_login", xn->text))
        return STEAM_ERROR_INVALID_LOGON;
    else if (!g_strcmp0("invalid_steamguard_code", xn->text))
        return STEAM_ERROR_INVALID_AUTH_CODE;
    else if (!g_strcmp0("steamguard_code_required", xn->text))
        return STEAM_ERROR_REQ_AUTH_CODE;

    return STEAM_ERROR_FAILED_AUTH;
}

static SteamError steam_api_friends_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    GSList         *fl;
    SteamError      err;

    if (!steam_util_xt_node(xr, "friends", &xn))
        return STEAM_ERROR_EMPTY_FRIENDS;

    if (xn->children == NULL)
        return STEAM_ERROR_EMPTY_FRIENDS;

    fl = NULL;

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xt_node(xn, "relationship", &xe))
            continue;

        if (g_strcmp0(xe->text, "friend"))
            continue;

        if (!steam_util_xt_node(xn, "steamid", &xe))
            continue;

        fl = g_slist_prepend(fl, xe->text);
    }

    priv->rdata = fl;
    priv->rfunc = (GDestroyNotify) g_slist_free;

    return (fl != NULL) ? STEAM_ERROR_SUCCESS : STEAM_ERROR_EMPTY_FRIENDS;
}

static SteamError steam_api_logon_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;

    if (!steam_util_xt_node(xr, "umqid", &xn))
        return STEAM_ERROR_EMPTY_UMQID;

    if (g_strcmp0(priv->api->umqid, xn->text))
        return STEAM_ERROR_MISMATCH_UMQID;

    if (!steam_util_xt_node(xr, "steamid", &xn))
        return STEAM_ERROR_EMPTY_STEAMID;

    g_free(priv->api->steamid);
    priv->api->steamid = g_strdup(xn->text);

    if (!steam_util_xt_node(xr, "message", &xn))
        return STEAM_ERROR_EMPTY_MESSAGE;

    g_free(priv->api->lmid);
    priv->api->lmid = g_strdup(xn->text);

    return STEAM_ERROR_SUCCESS;
}

static SteamError steam_api_logoff_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;

    if (!steam_util_xt_node(xr, "error", &xn))
        return STEAM_ERROR_FAILED_LOGOFF;

    if (g_strcmp0("OK", xn->text))
        return STEAM_ERROR_FAILED_LOGOFF;

    return STEAM_ERROR_SUCCESS;
}

static SteamError steam_api_message_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn;

    if (!steam_util_xt_node(xr, "error", &xn))
        return STEAM_ERROR_FAILED_MESSAGE_SEND;

    if (g_strcmp0("OK", xn->text))
        return STEAM_ERROR_FAILED_MESSAGE_SEND;

    return STEAM_ERROR_SUCCESS;
}

static SteamError steam_api_poll_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    SteamMessage   *sm;
    GSList         *mu;

    if (!steam_util_xt_node(xr, "messagelast", &xn))
        return STEAM_ERROR_SUCCESS;

    if (!g_strcmp0(priv->api->lmid, xn->text))
        return STEAM_ERROR_SUCCESS;

    g_free(priv->api->lmid);
    priv->api->lmid = g_strdup(xn->text);

    if (!steam_util_xt_node(xr, "messages", &xn))
        return STEAM_ERROR_SUCCESS;

    if (xn->children == NULL)
        return STEAM_ERROR_SUCCESS;

    mu = NULL;

    for (xn = xn->children; xn != NULL; xn = xn->next) {
        if (!steam_util_xt_node(xn, "steamid_from", &xe))
            continue;

        if (!g_strcmp0(priv->api->steamid, xe->text))
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

    priv->rdata = mu;
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;

    return STEAM_ERROR_SUCCESS;
}

static SteamError steam_api_summaries_cb(SteamApiPriv *priv, struct xt_node *xr)
{
    struct xt_node *xn, *xe;
    GSList         *mu;
    SteamSummary   *ss;
    SteamError      err;

    if (!steam_util_xt_node(xr, "players", &xn))
        return STEAM_ERROR_EMPTY_SUMMARY;

    if (xn->children == NULL)
        return STEAM_ERROR_EMPTY_SUMMARY;

    mu = NULL;

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

    priv->rdata = mu;
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;

    return (mu != NULL) ? STEAM_ERROR_SUCCESS : STEAM_ERROR_EMPTY_SUMMARY;
}

static void steam_api_parse(SteamApiPriv *priv, struct xt_node *xr)
{
    SteamParseFunc pf[STEAM_PAIR_LAST];

    pf[STEAM_PAIR_AUTH]      = steam_api_auth_cb;
    pf[STEAM_PAIR_FRIENDS]   = steam_api_friends_cb;
    pf[STEAM_PAIR_LOGON]     = steam_api_logon_cb;
    pf[STEAM_PAIR_LOGOFF]    = steam_api_logoff_cb;
    pf[STEAM_PAIR_MESSAGE]   = steam_api_message_cb;
    pf[STEAM_PAIR_POLL]      = steam_api_poll_cb;
    pf[STEAM_PAIR_SUMMARIES] = steam_api_summaries_cb;

    if ((priv->err == STEAM_ERROR_SUCCESS) && (xr != NULL))
        priv->err = pf[priv->type](priv, xr);

    if (priv->func != NULL) {
        switch (priv->type) {
        case STEAM_PAIR_AUTH:
        case STEAM_PAIR_LOGON:
        case STEAM_PAIR_LOGOFF:
        case STEAM_PAIR_MESSAGE:
            ((SteamApiFunc) priv->func)(priv->api, priv->err, priv->data);
            break;

        case STEAM_PAIR_FRIENDS:
        case STEAM_PAIR_POLL:
        case STEAM_PAIR_SUMMARIES:
            ((SteamListFunc) priv->func)(priv->api, priv->rdata, priv->err,
                                         priv->data);
            break;
        }
    }

    if (priv->rfunc)
        priv->rfunc(priv->rdata);
}

static gboolean steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamApiPriv     *priv = data;
    struct xt_parser *xt;
    struct xt_node   *xn;

    if ((priv->type < 0) || (priv->type > STEAM_PAIR_LAST))
        return TRUE;

    xt = NULL;

    if (req->body_size < 1) {
        priv->err = STEAM_ERROR_HTTP_EMPTY;
        goto parse;
    }

    switch (req->errcode) {
    case 200:
        break;

    case 400:
        priv->err = STEAM_ERROR_HTTP_BAD_REQUEST;
        goto parse;

    case 401:
        priv->err = STEAM_ERROR_HTTP_UNAUTHORIZED;
        goto parse;

    case 500:
        priv->err = STEAM_ERROR_HTTP_INT_SERVER;
        goto parse;

    case 503:
        priv->err = STEAM_ERROR_HTTP_UNAVAILABLE;
        goto parse;

    default:
        priv->err = STEAM_ERROR_HTTP_GENERIC;
        goto parse;
    }

    xt = xt_new(NULL, NULL);

    if (xt_feed(xt, req->body, req->body_size) < 0) {
        if (global.conf->verbose && (xt->gerr != NULL)) {
            g_print("  ** Markup parser error (%d): %s **\n\n",
                    xt->gerr->code, xt->gerr->message);
        }

        priv->err = STEAM_ERROR_PARSE_XML;
        goto parse;
    }

    if (steam_util_xt_node(xt->root, "error", &xn)) {
        if (!g_ascii_strncasecmp(xn->text, "Not Logged On", 13)) {
            priv->err = STEAM_ERROR_HTTP_UNAUTHORIZED;
            goto parse;
        }

        if (!g_ascii_strncasecmp(xn->text, "Service Unavailable", 19)) {
            priv->err = STEAM_ERROR_HTTP_UNAUTHORIZED;
            goto parse;
        }
    }

parse:
    if (xt != NULL) {
        steam_api_parse(priv, xt->root);
        xt_free(xt);
    } else {
        steam_api_parse(priv, NULL);
    }

    return TRUE;
}

void steam_api_auth(SteamAPI *api, const gchar *authcode,
                    const gchar *user, const gchar *pass,
                    SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_AUTH, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_AUTH, steam_api_cb, priv);

    steam_http_req_headers_set(req, 1, "User-Agent", STEAM_API_AGENT_AUTH);

    steam_http_req_params_set(req, 8,
        "format",          "xml",
        "client_id",       STEAM_API_CLIENT_ID,
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
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_FRIENDS, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_FRIENDS, steam_api_cb, priv);

    steam_http_req_params_set(req, 4,
        "format",       "xml",
        "access_token", api->token,
        "steamid",      api->steamid,
        "relationship", "friend"
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logon(SteamAPI *api, SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_LOGON, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_LOGON, steam_api_cb, priv);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_logoff(SteamAPI *api, SteamApiFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_LOGOFF, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_LOGOFF, steam_api_cb, priv);

    steam_http_req_params_set(req, 3,
        "format",       "xml",
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_message(SteamAPI *api, SteamMessage *sm, SteamApiFunc func,
                       gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);
    g_return_if_fail(sm  != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_MESSAGE, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_MESSAGE, steam_api_cb, priv);

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
        steam_http_req_free(req);
        return;
    }

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

void steam_api_poll(SteamAPI *api, SteamListFunc func, gpointer data)
{
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_POLL, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_POLL, steam_api_cb, priv);

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
    SteamHttpReq *req;
    SteamApiPriv *priv;

    GSList *s;
    GSList *e;
    GSList *l;

    gsize size;
    gint  i;

    gchar *str;
    gchar *p;

    g_return_if_fail(api != NULL);

    if (friends == NULL) {
        if (func != NULL)
            func(api, NULL, STEAM_ERROR_SUCCESS, data);

        return;
    }

    s  = friends;

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

        priv = steam_api_priv_new(STEAM_PAIR_SUMMARIES, api, func, data);
        req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                                  STEAM_PATH_SUMMARIES, steam_api_cb, priv);

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
    SteamHttpReq *req;
    SteamApiPriv *priv;

    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);

    priv = steam_api_priv_new(STEAM_PAIR_SUMMARIES, api, func, data);
    req  = steam_http_req_new(api->http, STEAM_API_HOST, 443,
                              STEAM_PATH_SUMMARIES, steam_api_cb, priv);

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

    strs[STEAM_ERROR_HTTP_BAD_REQUEST]    = "Bad HTTP request";
    strs[STEAM_ERROR_HTTP_EMPTY]          = "Empty HTTP reply returned";
    strs[STEAM_ERROR_HTTP_GENERIC]        = "Generic HTTP error returned";
    strs[STEAM_ERROR_HTTP_INT_SERVER]     = "Internal server error";
    strs[STEAM_ERROR_HTTP_UNAUTHORIZED]   = "Not authorized";
    strs[STEAM_ERROR_HTTP_UNAVAILABLE]    = "Service unavailable";

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
