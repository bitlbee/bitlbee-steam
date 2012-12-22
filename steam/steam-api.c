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

typedef void (*SteamParseFunc) (SteamApiPriv *priv, json_value *json);

enum _SteamApiType
{
    STEAM_PAIR_AUTH = 0,
    STEAM_PAIR_FRIENDS,
    STEAM_PAIR_LOGON,
    STEAM_PAIR_RELOGON,
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
    GError       *err;

    gpointer func;
    gpointer data;

    gpointer       rdata;
    GDestroyNotify rfunc;
};

static gboolean steam_api_logon_check(SteamApiPriv *priv, SteamHttpReq *req);

static SteamApiPriv *steam_api_priv_new(SteamApiType type, SteamAPI *api,
                                        gpointer func, gpointer data)
{
    SteamApiPriv *priv;

    priv = g_new0(SteamApiPriv, 1);

    priv->api  = api;
    priv->type = type;
    priv->func = func;
    priv->data = data;

    return priv;
}

static void steam_api_priv_free(SteamApiPriv *priv)
{
    g_return_if_fail(priv != NULL);

    if ((priv->rfunc != NULL) && (priv->rdata != NULL))
        priv->rfunc(priv->rdata);

    if (priv->err != NULL)
        g_error_free(priv->err);

    g_free(priv);
}

GQuark steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-api-error-quark");

    return q;
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

    api->http = steam_http_new(STEAM_API_AGENT,
                               (GDestroyNotify) steam_api_priv_free);

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

static void steam_api_auth_cb(SteamApiPriv *priv, json_value *json)
{
    SteamApiError  err;
    const gchar   *str;

    if (steam_util_json_str(json, "access_token", &str)) {
        g_free(priv->api->token);
        priv->api->token = g_strdup(str);
        return;
    }

    if (steam_util_json_scmp(json, "x_errorcode", "steamguard_code_required",
                             &str))
        err = STEAM_API_ERROR_AUTH_REQ;
    else
        err = STEAM_API_ERROR_AUTH;

    steam_util_json_str(json, "error_description", &str);
    g_set_error(&priv->err, STEAM_API_ERROR, err, "%s", str);
}

static void steam_api_friends_cb(SteamApiPriv *priv, json_value *json)
{
    json_value *jv;
    json_value *je;
    GSList     *fl;
    guint       i;

    const gchar *str;

    if (!steam_util_json_val(json, "friends", json_array, &jv))
        goto error;

    fl = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_util_json_scmp(je, "relationship", "friend", &str))
            continue;

        if (!steam_util_json_str(je, "steamid", &str))
            continue;

        fl = g_slist_prepend(fl, (gchar *) str);
    }

    priv->rdata = fl;
    priv->rfunc = (GDestroyNotify) g_slist_free;

    if (fl != NULL)
        return;

error:
    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIENDS,
                "Empty friends list");
}

static void steam_api_logon_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;

    if (!steam_util_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON,
                    "%s", str);
        return;
    }

    steam_util_json_str(json, "steamid", &str);
    g_free(priv->api->steamid);
    priv->api->steamid = g_strdup(str);

    steam_util_json_str(json, "message", &str);
    g_free(priv->api->lmid);
    priv->api->lmid = g_strdup(str);
}

static void steam_api_relogon_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar  *str;
    GSList       *l;

    priv->api->relog = FALSE;

    if (!steam_util_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_RELOGON,
                    "%s", str);
        return;
    }

    for (l = priv->api->rlreqs; l != NULL; l = l->next)
        steam_http_req_send(l->data);

    if (priv->api->rlreqs == NULL)
        return;

    g_slist_free(priv->api->rlreqs);
    priv->api->rlreqs = NULL;
}

static void steam_api_logoff_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;

    if (steam_util_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

static void steam_api_message_cb(SteamApiPriv *priv, json_value *json)
{
    const gchar *str;

    if (steam_util_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_MESSAGE,
                "%s", str);
}

static void steam_api_poll_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    json_value   *je;
    GSList       *mu;
    guint         i;
    SteamMessage  sm;

    const gchar *str;

    if (!steam_util_json_scmp(json, "messagelast", priv->api->lmid, &str)) {
        g_free(priv->api->lmid);
        priv->api->lmid = g_strdup(str);
    }

    if (!steam_util_json_scmp(json, "error", "Timeout", &str)) {
        if (g_strcmp0(str, "OK")) {
            g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        "%s", str);
            return;
        }
    }

    if (!steam_util_json_val(json, "messages", json_array, &jv))
        return;

    mu = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];
        memset(&sm, 0, sizeof sm);

        if (steam_util_json_scmp(je, "steamid_from", priv->api->steamid, &str))
            continue;

        sm.steamid = str;

        if (!steam_util_json_str(je, "type", &str))
            continue;

        if (!g_strcmp0("personastate", str)) {
            sm.type = STEAM_MESSAGE_TYPE_STATE;

            if (!steam_util_json_str(je, "persona_name", &sm.nick))
                continue;

            if (!steam_util_json_int(je, "persona_state", (gint *) &sm.state))
                continue;
        } else if (!g_strcmp0("saytext", str)) {
            sm.type = STEAM_MESSAGE_TYPE_SAYTEXT;

            if (!steam_util_json_str(je, "text", &sm.text))
                continue;
        } else if (!g_strcmp0("typing", str)) {
            sm.type = STEAM_MESSAGE_TYPE_TYPING;
        } else if (!g_strcmp0("emote", str)) {
            sm.type = STEAM_MESSAGE_TYPE_EMOTE;

            if (!steam_util_json_str(je, "text", &sm.text))
                continue;
        } else if (!g_strcmp0("leftconversation", str)) {
            sm.type = STEAM_MESSAGE_TYPE_LEFT_CONV;
        } else if (!g_strcmp0("personarelationship", str)) {
            sm.type = STEAM_MESSAGE_TYPE_RELATIONSHIP;

            if (!steam_util_json_int(je, "persona_state", (gint *) &sm.state))
                continue;
        } else {
            continue;
        }

        mu = g_slist_prepend(mu, g_memdup(&sm, sizeof sm));
    }

    priv->rdata = g_slist_reverse(mu);
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;
}

static void steam_api_summaries_cb(SteamApiPriv *priv, json_value *json)
{
    json_value   *jv;
    json_value   *je;
    GSList       *mu;
    SteamSummary  ss;
    guint         i;

    if (!steam_util_json_val(json, "players", json_array, &jv))
        goto error;

    mu = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];
        memset(&ss, 0, sizeof ss);

        if (!steam_util_json_str(je, "steamid", &ss.steamid))
            continue;

        steam_util_json_str(je, "gameextrainfo", &ss.game);
        steam_util_json_str(je, "gameserverip",  &ss.server);
        steam_util_json_str(je, "personaname",   &ss.nick);
        steam_util_json_str(je, "profileurl",    &ss.profile);
        steam_util_json_str(je, "realname",      &ss.fullname);
        steam_util_json_int(je, "personastate",  (gint *) &ss.state);

        mu = g_slist_prepend(mu, g_memdup(&ss, sizeof ss));
    }

    priv->rdata = mu;
    priv->rfunc = (GDestroyNotify) steam_slist_free_full;

    if (mu != NULL)
        return;

error:
    g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARIES,
                "No friends returned");
}

static gboolean steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamApiPriv  *priv = data;
    json_value    *json;
    json_settings  js;

    SteamParseFunc pf[STEAM_PAIR_LAST];
    gchar          err[128];

    if ((priv->type < 0) || (priv->type > STEAM_PAIR_LAST))
        return TRUE;

    json = NULL;

    if (req->err != NULL) {
        g_propagate_error(&priv->err, req->err);
        req->err = NULL;
        goto parse;
    }

    memset(&js, 0, sizeof js);
    json = json_parse_ex(&js, req->body, err);

    if (json == NULL) {
        g_set_error(&priv->err, STEAM_API_ERROR, STEAM_API_ERROR_PARSER,
                    "Parser: %s", err);
        goto parse;
    }

parse:
    pf[STEAM_PAIR_AUTH]      = steam_api_auth_cb;
    pf[STEAM_PAIR_FRIENDS]   = steam_api_friends_cb;
    pf[STEAM_PAIR_LOGON]     = steam_api_logon_cb;
    pf[STEAM_PAIR_RELOGON]   = steam_api_relogon_cb;
    pf[STEAM_PAIR_LOGOFF]    = steam_api_logoff_cb;
    pf[STEAM_PAIR_MESSAGE]   = steam_api_message_cb;
    pf[STEAM_PAIR_POLL]      = steam_api_poll_cb;
    pf[STEAM_PAIR_SUMMARIES] = steam_api_summaries_cb;

    if ((priv->err == NULL) && (json != NULL))
        pf[priv->type](priv, json);

    if (!steam_api_logon_check(priv, req)) {
        if (json != NULL)
            json_value_free(json);

        return FALSE;
    }

    if (priv->func != NULL) {
        switch (priv->type) {
        case STEAM_PAIR_AUTH:
        case STEAM_PAIR_LOGON:
        case STEAM_PAIR_RELOGON:
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

        default:
            break;
        }
    }

    if (json != NULL)
        json_value_free(json);

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
        "format",          STEAM_API_FORMAT,
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
        "format",       STEAM_API_FORMAT,
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
        "format",       STEAM_API_FORMAT,
        "access_token", api->token,
        "umqid",        api->umqid
    );

    req->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

static gboolean steam_api_logon_check(SteamApiPriv *priv, SteamHttpReq *req)
{
    SteamHttpReq *pr;
    SteamApiPriv *pp;

    g_return_val_if_fail(priv != NULL, FALSE);
    g_return_val_if_fail(req  != NULL, FALSE);

    if (priv->err == NULL)
        return TRUE;

    switch (priv->type) {
    case STEAM_PAIR_FRIENDS:
    case STEAM_PAIR_MESSAGE:
    case STEAM_PAIR_POLL:
    case STEAM_PAIR_SUMMARIES:
        break;

    default:
        return TRUE;
    }

    if (g_strncasecmp(priv->err->message, "Not Logged On", 13))
        return TRUE;

    priv->api->rlreqs = g_slist_prepend(priv->api->rlreqs, req);

    if (priv->api->relog)
        return FALSE;

    priv->api->relog = TRUE;

    pp = steam_api_priv_new(STEAM_PAIR_RELOGON, priv->api, NULL, NULL);
    pr = steam_http_req_new(priv->api->http, STEAM_API_HOST, 443,
                            STEAM_PATH_LOGON, steam_api_cb, pp);

    steam_http_req_params_set(pr, 3,
        "format",       "xml",
        "access_token", priv->api->token,
        "umqid",        priv->api->umqid
    );

    pr->flags = STEAM_HTTP_FLAG_POST | STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(pr);
    return FALSE;
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
        "format",       STEAM_API_FORMAT,
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
        "format",       STEAM_API_FORMAT,
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
        "format",       STEAM_API_FORMAT,
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
            func(api, NULL, NULL, data);

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
            "format",       STEAM_API_FORMAT,
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
        "format",       STEAM_API_FORMAT,
        "access_token", api->token,
        "steamids",     steamid
    );

    req->flags = STEAM_HTTP_FLAG_SSL;
    steam_http_req_send(req);
}

gchar *steam_message_type_str(SteamMessageType type)
{
    gchar *strs[STEAM_MESSAGE_TYPE_LAST];

    if ((type < 0) || (type > STEAM_MESSAGE_TYPE_LAST))
        return "";

    strs[STEAM_MESSAGE_TYPE_SAYTEXT]      = "saytext";
    strs[STEAM_MESSAGE_TYPE_EMOTE]        = "emote";
    strs[STEAM_MESSAGE_TYPE_LEFT_CONV]    = "leftconversation";
    strs[STEAM_MESSAGE_TYPE_RELATIONSHIP] = "personarelationship";
    strs[STEAM_MESSAGE_TYPE_STATE]        = "personastate";
    strs[STEAM_MESSAGE_TYPE_TYPING]       = "typing";

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
