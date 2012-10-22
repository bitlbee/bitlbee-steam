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
#include <string.h>

#include <bitlbee.h>
#include <http_client.h>

#include "steam-api.h"
#include "xmltree.h"

global_t global;

#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
    g_slist_foreach(list, (GFunc) free_func, NULL);
    g_slist_free(list);
}
#endif


#define steam_api_func(p, e) G_STMT_START{                   \
    if(p->func != NULL)                                      \
        (((SteamAPIFunc) p->func) (p->api, e, p->data));     \
}G_STMT_END

#define steam_list_func(p, l, e) G_STMT_START{               \
    if(p->func != NULL)                                      \
        (((SteamListFunc) p->func) (p->api, l, e, p->data)); \
}G_STMT_END


typedef enum   _SteamPairType SteamPairType;
typedef struct _SteamPair     SteamPair;
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
    GSList *fl;

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

        fl = g_slist_find_custom(fp->api->friends, xe->text,
                                 (GCompareFunc) g_strcmp0);

        if(fl == NULL)
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

static void steam_api_summaries_cb(SteamFuncPair *fp, struct xt_node *xr)
{
    struct xt_node *xn, *xe;

    GSList       *mu = NULL;
    SteamSummary *ss;

    if(!steam_xt_node_get(xr, "players", &xn)) {
        steam_list_func(fp, NULL, STEAM_ERROR_EMPTY_SUMMARY);
        return;
    }

    if(xn->children == NULL) {
        steam_list_func(fp, mu, STEAM_ERROR_EMPTY_SUMMARY);
        return;
    }

    for(xn = xn->children; xn != NULL; xn = xn->next) {
        if(!steam_xt_node_get(xn, "steamid", &xe))
            continue;

        ss = g_new0(SteamSummary, 1);
        ss->steamid = xe->text;

        if(steam_xt_node_get(xn, "personaname", &xe))
            ss->name = xe->text;

        if(steam_xt_node_get(xn, "personastate", &xe))
            ss->state = g_ascii_strtoll(xe->text, NULL, 10);

        if(steam_xt_node_get(xn, "profileurl", &xe))
            ss->profile = xe->text;

        if(steam_xt_node_get(xn, "realname", &xe))
            ss->realname = xe->text;

        mu = g_slist_append(mu, ss);
    }

    if(mu != NULL)
        steam_list_func(fp, mu, STEAM_ERROR_SUCCESS);
    else
        steam_list_func(fp, mu, STEAM_ERROR_EMPTY_SUMMARY);
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
    case STEAM_PAIR_SUMMARIES:
        steam_list_func(fp, NULL, err);
        break;
    }

    g_free(fp);
}

static void steam_api_cb(struct http_request *req)
{
    SteamFuncPair    *fp = req->data;
    struct xt_parser *xt;
    SteamError        err;

    gchar **ls;
    gint    i;

    fp->api->reqs = g_slist_remove(fp->api->reqs, fp->req);

    if((fp->type < 0) || (fp->type > STEAM_PAIR_LAST)) {
        g_free(fp);
        return;
    }

    if(global.conf->nofork && global.conf->verbose) {
        gchar *urls[STEAM_PAIR_LAST];

        urls[STEAM_PAIR_AUTH]      = "STEAM_PAIR_AUTH";
        urls[STEAM_PAIR_FRIENDS]   = "STEAM_PAIR_FRIENDS";
        urls[STEAM_PAIR_LOGON]     = "STEAM_PAIR_LOGON";
        urls[STEAM_PAIR_LOGOFF]    = "STEAM_PAIR_LOGOFF";
        urls[STEAM_PAIR_MESSAGE]   = "STEAM_PAIR_MESSAGE";
        urls[STEAM_PAIR_POLL]      = "STEAM_PAIR_POLL";
        urls[STEAM_PAIR_SUMMARIES] = "STEAM_PAIR_SUMMARIES";

        g_print("HTTP Reply (%s): %s\n", urls[fp->type], req->status_string);

        if(req->body_size > 0) {
            ls = g_strsplit(req->reply_body, "\n", 0);

            for(i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_print("\n");
            g_strfreev(ls);
        } else {
            g_print("  ** No HTTP data returned **");
        }
    }

    if(req->body_size < 1) {
        steam_api_cb_error(fp, STEAM_ERROR_HTTP_EMPTY);
        return;
    }

    if(req->status_code != 200) {
        steam_api_cb_error(fp, STEAM_ERROR_HTTP_GENERIC);
        return;
    }

    xt = xt_new(NULL, NULL);

    if(xt_feed(xt, req->reply_body, req->body_size) < 0) {
        steam_api_cb_error(fp, STEAM_ERROR_PARSE_XML);
        xt_free(xt);
        return;
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

void steam_api_summaries(SteamAPI *api, GSList *friends, SteamListFunc func,
                         gpointer data)
{
    GSList *s;
    GSList *e;
    GSList *l;

    gsize  size;
    gint   i;

    gchar *str;
    gchar *p;

    g_return_if_fail(api != NULL);

    if(friends == NULL)
        friends = api->friends;

    if(friends == NULL) {
        if(func != NULL)
            func(api, NULL, STEAM_ERROR_SUCCESS, data);

        return;
    }

    s = friends;

    while(TRUE) {
        size = 0;

        for(l = s, i = 0; (l != NULL) && (i < 100); l = l->next, i++)
            size += strlen(l->data) + 1;

        str = g_new0(gchar, size);
        p   = g_stpcpy(str, s->data);
        e   = l;

        for(l = s->next; l != e; l = l->next) {
            p = g_stpcpy(p, ",");
            p = g_stpcpy(p, l->data);
        }

        SteamPair ps[2] = {
            {"access_token", api->token},
            {"steamids",     str}
        };

        steam_api_req(STEAM_PATH_SUMMARIES, ps, 2, TRUE, FALSE,
                      steam_pair_new(STEAM_PAIR_SUMMARIES, api, func, data));

        g_free(str);

        if(e != NULL)
            s = e->next;
        else
            break;
    }
}

void steam_api_summary(SteamAPI *api, gchar *steamid, SteamListFunc func,
                       gpointer data)
{
    g_return_if_fail(api     != NULL);
    g_return_if_fail(steamid != NULL);

    SteamPair ps[2] = {
        {"access_token", api->token},
        {"steamids",     steamid}
    };

    steam_api_req(STEAM_PATH_SUMMARIES, ps, 2, TRUE, FALSE,
                  steam_pair_new(STEAM_PAIR_SUMMARIES, api, func, data));
}

gchar *steam_api_error_str(SteamError err)
{
    gchar *strs[STEAM_ERROR_LAST];

    if((err < 0) || (err > STEAM_ERROR_LAST))
        return "";

    strs[STEAM_ERROR_SUCCESS]             = "Success";

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

    if((type < 0) || (type > STEAM_MESSAGE_TYPE_LAST))
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

    if((state < 0) || (state > STEAM_STATE_LAST))
        return "";

    strs[STEAM_STATE_OFFLINE] = "Offline";
    strs[STEAM_STATE_ONLINE]  = "Online";
    strs[STEAM_STATE_BUSY]    = "Busy";
    strs[STEAM_STATE_AWAY]    = "Away";
    strs[STEAM_STATE_SNOOZE]  = "Snooze";

    return strs[state];
}
