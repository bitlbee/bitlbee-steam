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

#include <string.h>
#include <url.h>

#include "steam-api.h"
#include "steam-crypt.h"
#include "steam-http.h"
#include "steam-json.h"
#include "steam-util.h"

GQuark
steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("steam-api-error-quark");
    }

    return q;
}

SteamApi *
steam_api_new(void)
{
    SteamApi *api;

    api = g_new0(SteamApi, 1);
    api->info = steam_user_info_new(0);
    api->http = steam_http_new(STEAM_API_AGENT);
    api->msgs = g_queue_new();

    return api;
}

void
steam_api_free_auth(SteamApi *api)
{
    if (G_UNLIKELY(api == NULL)) {
        return;
    }

    g_free(api->pktime);
    g_free(api->pkexp);
    g_free(api->pkmod);
    g_free(api->esid);
    g_free(api->cgid);

    api->pktime = NULL;
    api->pkexp = NULL;
    api->pkmod = NULL;
    api->esid = NULL;
    api->cgid = NULL;
}

void
steam_api_free(SteamApi *api)
{
    if (G_UNLIKELY(api == NULL)) {
        return;
    }

    g_queue_free_full(api->msgs, (GDestroyNotify) steam_api_req_free);

    steam_http_free(api->http);
    steam_user_info_free(api->info);
    steam_api_free_auth(api);

    g_free(api->sessid);
    g_free(api->token);
    g_free(api->umqid);
    g_free(api);
}

gchar *
steam_api_captcha_url(const gchar *cgid)
{
    g_return_val_if_fail(cgid != NULL, NULL);

    return g_strdup_printf("https://%s%s?gid=%s", STEAM_COM_HOST,
                           STEAM_COM_PATH_CAPTCHA, cgid);
}

void
steam_api_rehash(SteamApi *api)
{
    gchar *str;

    g_return_if_fail(api != NULL);

    if (api->umqid == NULL) {
        api->umqid = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());
    }

    if ((api->info->id != 0) && (api->token != NULL)) {
        str = g_strdup_printf("%" STEAM_ID_FORMAT "||oauth:%s",
                              api->info->id, api->token);

        steam_http_cookies_set(api->http,
            STEAM_HTTP_PAIR("steamLogin", str),
            NULL
        );

        g_free(str);
    }

    steam_http_cookies_set(api->http,
        STEAM_HTTP_PAIR("forceMobile", "1"),
        STEAM_HTTP_PAIR("mobileClient", STEAM_API_CLIENT),
        STEAM_HTTP_PAIR("mobileClientVersion", STEAM_API_CLIENT_VERSION),
        STEAM_HTTP_PAIR("sessionid", api->sessid),
        NULL
    );
}

static void
steam_api_json_error(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gboolean bool;
    gint64 in;
    guint errc;

    if (steam_json_str_chk(json, "error", &str)) {
        if (g_ascii_strcasecmp(str, "OK") == 0) {
            return;
        }

        if (g_ascii_strcasecmp(str, "Timeout") == 0) {
            return;
        }

        if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
            req->api->online = FALSE;
            errc = STEAM_API_ERROR_EXPRIED;
            str = "Session expired";
        } else {
            errc = STEAM_API_ERROR_GENERAL;
        }

        g_set_error(&req->err, STEAM_API_ERROR, errc, "%s", str);
        return;
    }

    if (steam_json_bool_chk(json, "success", &bool) && !bool) {
        if (steam_json_bool_chk(json, "captcha_needed", &bool) && bool) {
            return;
        }

        if (steam_json_bool_chk(json, "emailauth_needed", &bool) && bool) {
            return;
        }

        if (steam_json_bool_chk(json, "requires_twofactor", &bool) && bool) {
            return;
        }

        if (!steam_json_str_chk(json, "message", &str)) {
            str = "Unknown error";
        }

        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_UNKNOWN,
                    "%s", str);
        return;
    }

    if (steam_json_int_chk(json, "sectimeout", &in) &&
        (in < STEAM_API_TIMEOUT))
    {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Timeout of %" G_GINT64_FORMAT " too low", in);
        return;
    }
}

static void
steam_api_json_user_info(SteamUserInfo *info, const json_value *json)
{
    const gchar *str;
    const gchar *tmp;
    gint64 in;

    if (steam_json_str_chk(json, "gameextrainfo", &str)) {
        g_free(info->game);

        if (steam_json_str_chk(json, "gameid", &tmp)) {
            info->game = g_strdup(str);
        } else {
            info->game = g_strdup_printf("Non-Steam: %s", str);
        }
    }

    if (steam_json_str_chk(json, "gameserverip", &str)) {
        g_free(info->server);
        info->server = g_strdup(str);
    }

    if (steam_json_str_chk(json, "personaname", &str)) {
        g_free(info->nick);
        info->nick = g_strdup(str);
    }

    if (steam_json_str_chk(json, "profileurl", &str)) {
        g_free(info->profile);
        info->profile = g_strdup(str);
    }

    if (steam_json_str_chk(json, "realname", &str)) {
        g_free(info->fullname);
        info->fullname = g_strdup(str);
    }

    if (steam_json_int_chk(json, "lastlogoff", &in)) {
        info->ltime = in;
    }

    if (steam_json_int_chk(json, "personastate", &in)) {
        info->state = in;
    }

    if (steam_json_int_chk(json, "personastateflags", &in)) {
        info->flags = in;
    }
}

SteamApiReq *
steam_api_req_new(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_val_if_fail(api != NULL, NULL);

    req = g_new0(SteamApiReq, 1);
    req->api = api;
    req->func = func;
    req->data = data;
    req->msgs = g_queue_new();
    req->infs = g_queue_new();
    req->infr = g_queue_new();

    return req;
}

SteamApiReq *
steam_api_req_fwd(SteamApiReq *req)
{
    SteamApiReq *deq;

    g_return_val_if_fail(req != NULL, NULL);

    deq = g_memdup(req, sizeof *req);
    deq->flags = 0;
    deq->req = NULL;
    deq->punc = NULL;

    req->err = NULL;
    req->func = NULL;
    req->data = NULL;
    req->msgs = g_queue_new();
    req->infs = g_queue_new();
    req->infr = g_queue_new();

    return deq;
}

void
steam_api_req_free(SteamApiReq *req)
{
    GHashTable *tbl;
    GList *l;
    GList *n;
    SteamUserMsg *msg;

    if (G_UNLIKELY(req == NULL)) {
        return;
    }

    tbl = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (l = req->msgs->head; l != NULL; l = l->next) {
        msg = l->data;
        g_hash_table_replace(tbl, msg->info, msg->info);
    }

    for (l = req->infs->head; l != NULL; l = n) {
        n = l->next;

        if (g_hash_table_lookup_extended(tbl, l->data, NULL, NULL)) {
            g_queue_delete_link(req->infs, l);
        }
    }

    g_queue_free_full(req->infs, (GDestroyNotify) steam_user_info_free);
    g_queue_free_full(req->msgs, (GDestroyNotify) steam_user_msg_free);

    g_queue_free(req->infr);
    g_hash_table_destroy(tbl);

    if (req->err != NULL) {
        g_error_free(req->err);
    }

    g_free(req);
}

static void
steam_api_req_cb(SteamHttpReq *heq, gpointer data)
{
    json_value *json = NULL;
    SteamApiReq *req = data;

    req->req = heq;

    if (G_LIKELY(req->err == NULL)) {
        if (heq->err != NULL) {
            g_propagate_error(&req->err, heq->err);
            heq->err = NULL;
        }

        if (!(req->flags & STEAM_API_REQ_FLAG_NOJSON) && (req->err == NULL)) {
            json = steam_json_new(heq->body, heq->body_size, &req->err);

            if (req->err == NULL) {
                steam_api_json_error(req, json);
            }
        }

        if ((req->punc != NULL) && (req->err == NULL)) {
            req->punc(req, json);
        }

        if (json != NULL) {
            json_value_free(json);
        }
    }

    if (req->func != NULL) {
        g_queue_remove(req->infs, req->api->info);
        req->func(req, req->data);
    }

    steam_api_req_free(req);
}

void
steam_api_req_init(SteamApiReq *req, const gchar *host, const gchar *path)
{
    SteamApi *api = req->api;
    SteamHttpReq *heq;

    g_return_if_fail(req != NULL);
    g_return_if_fail(api != NULL);
    g_return_if_fail(host != NULL);
    g_return_if_fail(path != NULL);

    heq = steam_http_req_new(api->http, host, 443, path, steam_api_req_cb, req);
    heq->flags = STEAM_HTTP_REQ_FLAG_SSL;
    req->req = heq;
}

static void
steam_api_cb_user_info_req(SteamApiReq *req, const json_value *json)
{
    req = steam_api_req_fwd(req);
    steam_api_req_user_info(req);
}

static void
steam_api_cb_auth_finish(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    steam_http_cookies_parse_req(req->api->http, req->req);
    str = steam_http_cookies_get(req->api->http, "sessionid");

    if (str == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to obtain sessionid");
        return;
    }

    g_free(req->api->sessid);
    req->api->sessid = g_strdup(str);
}

static void
steam_api_cb_auth_rdir(SteamApiReq *req, const json_value *json)
{
    req = steam_api_req_fwd(req);
    req->punc = steam_api_cb_auth_finish;
    steam_api_req_init(req, STEAM_COM_HOST, "/");

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    steam_http_req_send(req->req);
}

static void
steam_api_cb_auth(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gboolean bln;
    gchar *val;
    guint errc;
    guint i;
    json_value *jp;
    json_value *jv;

    if (steam_json_bool_chk(json, "success", &bln) && !bln) {
        if (steam_json_bool_chk(json, "requires_twofactor", &bln) && bln) {
            req->api->autht = STEAM_API_AUTH_TYPE_MOBILE;
            errc = STEAM_API_ERROR_STEAMGUARD;
        } else if (steam_json_bool_chk(json, "emailauth_needed", &bln) && bln) {
            req->api->autht = STEAM_API_AUTH_TYPE_EMAIL;
            errc = STEAM_API_ERROR_STEAMGUARD;
            str = steam_json_str(json, "emailsteamid");

            g_free(req->api->esid);
            req->api->esid = g_strdup(str);
        } else if (steam_json_bool_chk(json, "captcha_needed", &bln) && bln) {
            errc = STEAM_API_ERROR_CAPTCHA;
            str = steam_json_str(json, "captcha_gid");

            g_free(req->api->cgid);
            req->api->cgid = g_strdup(str);
        } else {
            errc = STEAM_API_ERROR_UNKNOWN;
        }

        if (errc == STEAM_API_ERROR_STEAMGUARD) {
            str = "SteamGuard authentication code required";
        } else {
            str = steam_json_str(json, "message");
        }

        g_set_error(&req->err, STEAM_API_ERROR, errc, "%s", str);
        return;
    }

    if (!steam_json_val_chk(json, "oauth", json_string, &jv)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to obtain OAuth data");
        return;
    }

    jp = steam_json_new(jv->u.string.ptr, jv->u.string.length, &req->err);

    if ((jp == NULL) || (req->err != NULL)) {
        return;
    }

    if (steam_json_str_chk(jp, "oauth_token", &str)) {
        g_free(req->api->token);
        req->api->token = g_strdup(str);
    }

    req = steam_api_req_fwd(req);
    req->punc = steam_api_cb_auth_rdir;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH_RDIR);

    for (i = 0; i < jp->u.object.length; i++) {
        str = jp->u.object.values[i].name;
        jv = jp->u.object.values[i].value;
        val = steam_json_valstr(jv);

        steam_http_req_params_set(req->req, STEAM_HTTP_PAIR(str, val), NULL);
        g_free(val);
    }

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
    json_value_free(jp);
}

void
steam_api_req_auth(SteamApiReq *req, const gchar *user, const gchar *pass,
                   const gchar *authcode, const gchar *captcha)
{
    gchar *ms;
    gchar *pswd;
    GTimeVal tv;

    g_return_if_fail(req != NULL);
    g_return_if_fail(user != NULL);
    g_return_if_fail(pass != NULL);

    pswd = steam_crypt_rsa_enc_str(req->api->pkmod, req->api->pkexp, pass);

    if (pswd == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to encrypt password");

        if (req->func != NULL) {
            req->func(req, req->data);
        }

        steam_api_req_free(req);
        return;
    }

    req->punc = steam_api_cb_auth;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    switch (req->api->autht) {
    case STEAM_API_AUTH_TYPE_EMAIL:
        steam_http_req_params_set(req->req,
            STEAM_HTTP_PAIR("emailauth",    authcode),
            STEAM_HTTP_PAIR("emailsteamid", req->api->esid),
            NULL
        );
        break;

    case STEAM_API_AUTH_TYPE_MOBILE:
        steam_http_req_params_set(req->req,
            STEAM_HTTP_PAIR("twofactorcode", authcode),
            NULL
        );
        break;

    default:
        break;
    }

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("username", user),
        STEAM_HTTP_PAIR("password", pswd),
        STEAM_HTTP_PAIR("captchagid", req->api->cgid),
        STEAM_HTTP_PAIR("captcha_text", captcha),
        STEAM_HTTP_PAIR("rsatimestamp", req->api->pktime),
        STEAM_HTTP_PAIR("loginfriendlyname", PACKAGE),
        STEAM_HTTP_PAIR("oauth_client_id", STEAM_API_CLIENT_ID),
        STEAM_HTTP_PAIR("donotcache", ms),
        STEAM_HTTP_PAIR("remember_login", "true"),
        STEAM_HTTP_PAIR("oauth_scope", "read_profile write_profile "
                                             "read_client write_client"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(pswd);
    g_free(ms);
}

static void
steam_api_cb_friends(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    guint i;
    json_value *je;
    json_value *jv;
    SteamUserInfo *info;
    SteamUserRel rel;

    if (!steam_json_array_chk(json, "friends", &jv)) {
        return;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "relationship", &str)) {
            continue;
        }

        if (g_ascii_strcasecmp(str, "friend") == 0) {
            rel = STEAM_USER_REL_FRIEND;
        } else if (g_ascii_strcasecmp(str, "ignoredfriend") == 0) {
            rel = STEAM_USER_REL_IGNORE;
        } else {
            continue;
        }

        if (!steam_json_str_chk(je, "steamid", &str)) {
            continue;
        }

        info = steam_user_info_new(STEAM_ID_NEW_STR(str));
        info->rel = rel;
        g_queue_push_tail(req->infs, info);
    }

    req = steam_api_req_fwd(req);
    steam_api_req_msg_info(req);
}

void
steam_api_req_friends(SteamApiReq *req)
{
    gchar sid[STEAM_ID_STRMAX];

    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_friends;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIENDS);
    STEAM_ID_STR(req->api->info->id, sid);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamid", sid),
        STEAM_HTTP_PAIR("relationship", "friend,ignoredfriend"),
        NULL
    );

    steam_http_req_send(req->req);
}

static void
steam_api_cb_key(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (steam_json_str_chk(json, "publickey_mod", &str)) {
        g_free(req->api->pkmod);
        req->api->pkmod = g_strdup(str);
    }

    if (steam_json_str_chk(json, "publickey_exp", &str)) {
        g_free(req->api->pkexp);
        req->api->pkexp = g_strdup(str);
    }

    if (steam_json_str_chk(json, "timestamp", &str)) {
        g_free(req->api->pktime);
        req->api->pktime = g_strdup(str);
    }
}

void
steam_api_req_key(SteamApiReq *req, const gchar *user)
{
    gchar *ms;
    GTimeVal tv;

    g_return_if_fail(req != NULL);
    g_return_if_fail(user != NULL);

    req->punc = steam_api_cb_key;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_KEY);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("username", user),
        STEAM_HTTP_PAIR("donotcache", ms),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
    g_free(ms);
}

void
steam_api_req_logoff(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGOFF);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid", req->api->umqid),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

static void
steam_api_cb_logon(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (steam_json_str_chk(json, "steamid", &str)) {
        req->api->info->id = STEAM_ID_NEW_STR(str);
        g_queue_push_tail(req->infs, req->api->info);
        steam_api_rehash(req->api);
    }

    if (steam_json_str_chk(json, "umqid", &str)) {
        g_free(req->api->umqid);
        req->api->umqid = g_strdup(str);
        steam_api_rehash(req->api);
    }

    req->api->lmid = steam_json_int(json, "message");
    req->api->time = steam_json_int(json, "utc_timestamp");

    /* Ensure the #SteamApi online state */
    req->api->online = TRUE;

    /* If this is a relogon, process queued messages */
    if (!g_queue_is_empty(req->api->msgs)) {
        req = g_queue_pop_head(req->api->msgs);
        steam_http_req_send(req->req);
    }

    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_logon(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_logon;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid", req->api->umqid),
        STEAM_HTTP_PAIR("ui_mode", "web"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

static void
steam_api_cb_msg(SteamApiReq *req, const json_value *json)
{
    /* Pop the successful message request */
    g_queue_pop_head(req->api->msgs);

    if (!g_queue_is_empty(req->api->msgs)) {
        req = g_queue_peek_head(req->api->msgs);
        steam_http_req_send(req->req);
    }
}

void
steam_api_req_msg(SteamApiReq *req, const SteamUserMsg *msg)
{
    const gchar *type;
    gboolean empty;
    gchar sid[STEAM_ID_STRMAX];

    g_return_if_fail(req != NULL);
    g_return_if_fail(msg != NULL);

    req->punc = steam_api_cb_msg;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGE);

    STEAM_ID_STR(msg->info->id, sid);
    type = steam_user_msg_type_str(msg->type);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid", req->api->umqid),
        STEAM_HTTP_PAIR("steamid_dst", sid),
        STEAM_HTTP_PAIR("type", type),
        NULL
    );

    switch (msg->type) {
    case STEAM_USER_MSG_TYPE_SAYTEXT:
    case STEAM_USER_MSG_TYPE_EMOTE:
        steam_http_req_params_set(req->req,
            STEAM_HTTP_PAIR("text", msg->text),
            NULL
        );
        break;

    case STEAM_USER_MSG_TYPE_TYPING:
        break;

    default:
        steam_http_req_free(req->req);
        return;
    }

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    empty = g_queue_is_empty(req->api->msgs);
    g_queue_push_tail(req->api->msgs, req);

    if (empty && req->api->online) {
        steam_http_req_send(req->req);
    }
}

static void
steam_api_cb_msg_info(SteamApiReq *req, const json_value *json)
{
    GHashTable *ght;
    gint64 in;
    GList *l;
    guint i;
    json_value *je;
    json_value *jv;
    SteamId id;
    SteamUserInfo *info;

    if (!steam_json_val_chk(json, "response", json_object, &jv) ||
        !steam_json_array_chk(jv, "message_sessions", &jv))
    {
        steam_api_cb_user_info_req(req, json);
        return;
    }

    ght = g_hash_table_new(steam_id_hash, steam_id_equal);

    for (l = req->infs->head; l != NULL; l = l->next) {
        info = l->data;
        g_hash_table_replace(ght, &info->id, info);
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_int_chk(je, "accountid_friend", &in)) {
            continue;
        }

        id = STEAM_ID_NEW(STEAM_ID_UNIV_PUBLIC, STEAM_ID_TYPE_INDIVIDUAL,
                          STEAM_ID_INST_DESKTOP, in);

        info = g_hash_table_lookup(ght, &id);

        if (G_UNLIKELY(info == NULL)) {
            continue;
        }

        if (steam_json_int_chk(je, "last_view", &in)) {
            info->vtime = in;
        }

        if (steam_json_int_chk(je, "unread_message_count", &in)) {
            info->unread = in;
        }
    }

    g_hash_table_destroy(ght);
    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_msg_info(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->infs == NULL) {
        if (req->func != NULL) {
            req->func(req, req->data);
        }

        steam_api_req_free(req);
        return;
    }

    req->punc = steam_api_cb_msg_info;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGE_INFO);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        NULL
    );

    steam_http_req_send(req->req);
}

static void
steam_api_cb_msgs(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gint32 aid;
    gint64 in;
    guint i;
    json_value *je;
    json_value *jv;
    SteamId id;
    SteamUserMsg *msg = NULL;

    if (!steam_json_val_chk(json, "response", json_object, &jv) ||
        !steam_json_array_chk(jv, "messages", &jv))
    {
        return;
    }

    aid = STEAM_ID_ACCID(req->api->info->id);

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_int_chk(je, "accountid", &in) || (in == aid)) {
            continue;
        }

        id = STEAM_ID_NEW(STEAM_ID_UNIV_PUBLIC, STEAM_ID_TYPE_INDIVIDUAL,
                          STEAM_ID_INST_DESKTOP, in);

        msg = steam_user_msg_new(id);
        msg->type = STEAM_USER_MSG_TYPE_SAYTEXT;
        msg->time = steam_json_int(je, "timestamp");

        str = steam_json_str(je, "message");
        msg->text = g_strdup(str);

        /* Messages are send backwards */
        g_queue_push_head(req->msgs, msg);
        g_queue_push_tail(req->infs, msg->info);
    }

    if (msg != NULL) {
        req = steam_api_req_fwd(req);
        steam_api_req_msgs_read(req, msg->info->id);
    }
}

void
steam_api_req_msgs(SteamApiReq *req, SteamId id, gint64 since)
{
    gchar sid1[STEAM_ID_STRMAX];
    gchar sid2[STEAM_ID_STRMAX];
    gchar *stime;

    g_return_if_fail(req != NULL);
    req->punc = steam_api_cb_msgs;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGES);

    STEAM_ID_STR(id, sid1);
    STEAM_ID_STR(req->api->info->id, sid2);
    stime = g_strdup_printf("%" G_GINT64_FORMAT, since);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamid1", sid1),
        STEAM_HTTP_PAIR("steamid2", sid2),
        STEAM_HTTP_PAIR("rtime32_start_time", stime),
        NULL
    );

    steam_http_req_send(req->req);
    g_free(stime);
}

void
steam_api_req_msgs_read(SteamApiReq *req, SteamId id)
{
    gchar sid[STEAM_ID_STRMAX];

    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_user_info_req;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGES_READ);
    STEAM_ID_STR(id, sid);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamid_friend", sid),
        NULL
    );

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

static void
steam_api_cb_poll(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gboolean selfie = FALSE;
    gint64 in;
    guint i;
    json_value *je;
    json_value *jv;
    SteamId id;
    SteamUserMsg *msg;

    if (!steam_json_int_chk(json, "messagelast", &in) ||
        (in == req->api->lmid))
    {
        return;
    }

    req->api->lmid = in;

    if (!steam_json_array_chk(json, "messages", &jv)) {
        return;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "steamid_from", &str)) {
            continue;
        }

        id = STEAM_ID_NEW_STR(str);

        if (id == req->api->info->id) {
            selfie = TRUE;
            continue;
        }

        /* For now, only handle individuals */
        if (STEAM_ID_TYPE(id) != STEAM_ID_TYPE_INDIVIDUAL) {
            continue;
        }

        msg = steam_user_msg_new(id);
        str = steam_json_str(je, "type");

        msg->type = steam_user_msg_type_from_str(str);
        msg->time = steam_json_int(je, "utc_timestamp");

        switch (msg->type) {
        case STEAM_USER_MSG_TYPE_MY_SAYTEXT:
        case STEAM_USER_MSG_TYPE_MY_EMOTE:
        case STEAM_USER_MSG_TYPE_SAYTEXT:
        case STEAM_USER_MSG_TYPE_EMOTE:
            str = steam_json_str(je, "text");
            msg->text = g_strdup(str);
            break;

        case STEAM_USER_MSG_TYPE_RELATIONSHIP:
            msg->info->act = steam_json_int(je, "persona_state");
            break;

        case STEAM_USER_MSG_TYPE_STATE:
        case STEAM_USER_MSG_TYPE_TYPING:
        case STEAM_USER_MSG_TYPE_LEFT_CONV:
            break;

        default:
            steam_user_msg_free(msg);
            continue;
        }

        g_queue_push_tail(req->msgs, msg);
        g_queue_push_tail(req->infs, msg->info);
    }

    if (selfie) {
        g_queue_push_tail(req->infs, req->api->info);
    }

    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_poll(SteamApiReq *req)
{
    const gchar *idle;
    gchar *lmid;
    gchar *tout;

    static const SteamUtilEnum enums[] = {
        {STEAM_USER_STATE_AWAY, G_STRINGIFY(STEAM_API_IDLEOUT_AWAY)},
        {STEAM_USER_STATE_SNOOZE, G_STRINGIFY(STEAM_API_IDLEOUT_SNOOZE)},
        STEAM_UTIL_ENUM_NULL
    };

    g_return_if_fail(req != NULL);

    idle = steam_util_enum_ptr(enums, "0", req->api->info->state);
    lmid = g_strdup_printf("%" G_GINT64_FORMAT, req->api->lmid);
    tout = g_strdup_printf("%" G_GINT32_FORMAT, STEAM_API_TIMEOUT);

    req->punc = steam_api_cb_poll;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_POLL);

    steam_http_req_headers_set(req->req,
        STEAM_HTTP_PAIR("Connection", "Keep-Alive"),
        NULL
    );

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid", req->api->umqid),
        STEAM_HTTP_PAIR("message", lmid),
        STEAM_HTTP_PAIR("sectimeout", tout),
        STEAM_HTTP_PAIR("secidletime", idle),
        NULL
    );

    req->req->timeout = (STEAM_API_TIMEOUT + 5) * 1000;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(tout);
    g_free(lmid);
}

void
steam_api_req_user_accept(SteamApiReq *req, SteamId id,
                          SteamApiAcceptType type)
{
    const gchar *sct;
    gchar sid[STEAM_ID_STRMAX];
    gchar *srl;
    SteamUserInfo *info;
    url_t url;

    static const SteamUtilEnum enums[] = {
        {STEAM_API_ACCEPT_TYPE_DEFAULT, "accept"},
        {STEAM_API_ACCEPT_TYPE_BLOCK, "block"},
        {STEAM_API_ACCEPT_TYPE_IGNORE, "ignore"},
        STEAM_UTIL_ENUM_NULL
    };

    g_return_if_fail(req != NULL);

    sct = steam_util_enum_ptr(enums, NULL, type);
    srl = steam_http_uri_join(req->api->info->profile, "home_process", NULL);
    url_set(&url, srl);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_info_req;
    steam_api_req_init(req, url.host, url.file);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("id", sid),
        STEAM_HTTP_PAIR("perform", sct),
        STEAM_HTTP_PAIR("action", "approvePending"),
        STEAM_HTTP_PAIR("itype", "friend"),
        STEAM_HTTP_PAIR("json", "1"),
        STEAM_HTTP_PAIR("xml", "0"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(srl);
}

static void
steam_api_cb_user_add(SteamApiReq *req, const json_value *json)
{
    gint64 in;

    if (!steam_json_int_chk(json, "success", &in) || (in == 0)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to add friend");
        return;
    }

    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_user_add(SteamApiReq *req, SteamId id)
{
    gchar sid[STEAM_ID_STRMAX];
    SteamUserInfo *info;

    g_return_if_fail(req != NULL);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_add;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_ADD);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("steamid", sid),
        STEAM_HTTP_PAIR("accept_invite", "0"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

void
steam_api_req_user_ignore(SteamApiReq *req, SteamId id, gboolean ignore)
{
    const gchar *act;
    gchar *srl;
    gchar *user;
    SteamUserInfo *info;
    url_t url;

    g_return_if_fail(req != NULL);

    act = ignore ? "ignore" : "unignore";
    user = g_strdup_printf("friends[%" STEAM_ID_FORMAT "]", id);
    srl = steam_http_uri_join(req->api->info->profile, "friends", NULL);
    url_set(&url, srl);

    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_info_req;
    steam_api_req_init(req, url.host, url.file);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("action", act),
        STEAM_HTTP_PAIR(user, "1"),
        NULL
    );

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(srl);
    g_free(user);
}

static void
steam_api_cb_user_info(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    GHashTable *ght;
    GList *l;
    GList *n;
    gpointer key;
    guint i;
    json_value *je;
    json_value *jv;
    SteamId id;
    SteamUserInfo *info;

    if ((!steam_json_array_chk(json, "players", &jv) ||
         (jv->u.array.length < 1)) && (req->infs != NULL))
    {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to retrieve requested friend summaries");
        return;
    }

    ght = g_hash_table_new_full(steam_id_hash, steam_id_equal, g_free, NULL);

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (steam_json_str_chk(je, "steamid", &str)) {
            id = STEAM_ID_NEW_STR(str);
            key = g_memdup(&id, sizeof id);
            g_hash_table_replace(ght, key, je);
        }
    }

    for (l = req->infr->head; l != NULL; l = n) {
        info = l->data;
        n = l->next;
        je = g_hash_table_lookup(ght, &info->id);

        if (je != NULL) {
            steam_api_json_user_info(info, je);
            g_queue_delete_link(req->infr, l);
        }
    }

    if (!g_queue_is_empty(req->infr)) {
        req = steam_api_req_fwd(req);
        steam_api_req_user_info(req);
    }

    g_hash_table_destroy(ght);
}

void
steam_api_req_user_info(SteamApiReq *req)
{
    GHashTable *ght;
    GList *l;
    GList *n;
    gsize i;
    GString *gstr;
    SteamId *id;
    SteamUserInfo *info;

    g_return_if_fail(req != NULL);

    if (G_UNLIKELY(g_queue_is_empty(req->infs))) {
        if (req->func != NULL) {
            req->func(req, req->data);
        }

        steam_api_req_free(req);
        return;
    }

    if (g_queue_is_empty(req->infr)) {
        g_queue_free(req->infr);
        req->infr = g_queue_copy(req->infs);
    }

    ght = g_hash_table_new(g_int64_hash, g_int64_equal);
    gstr = g_string_new(NULL);

    for (l = req->infr->head, i = 0; l != NULL; l = n) {
        info = l->data;
        n = l->next;
        id = &info->id;

        if (!g_hash_table_lookup_extended(ght, id, NULL, NULL)) {
            g_hash_table_replace(ght, id, id);
            g_string_append_printf(gstr, "%" STEAM_ID_FORMAT ",", info->id);

            if ((++i % 100) == 0) {
                break;
            }
        }
    }

    /* Remove trailing comma */
    gstr->str[gstr->len - 1] = 0;

    req->punc = steam_api_cb_user_info;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamids", gstr->str),
        NULL
    );

    steam_http_req_send(req->req);
    g_string_free(gstr, TRUE);
    g_hash_table_destroy(ght);
}

static void
steam_api_cb_user_info_nicks(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    guint i;
    json_value *je;
    SteamUserInfo *info;

    info = g_queue_pop_head(req->infr);

    for (i = 0; i < json->u.array.length; i++) {
        je = json->u.array.values[i];

        if (!steam_json_str_chk(je, "newname", &str)) {
            continue;
        }

        if (g_strcmp0(str, info->nick) != 0) {
            info->nicks = g_slist_prepend(info->nicks, g_strdup(str));
        }
    }

    info->nicks = g_slist_reverse(info->nicks);

    if (!g_queue_is_empty(req->infr)) {
        req = steam_api_req_fwd(req);
        steam_api_req_user_info_nicks(req);
    }
}

void
steam_api_req_user_info_nicks(SteamApiReq *req)
{
    gchar *srl;
    SteamUserInfo *info;
    url_t url;

    g_return_if_fail(req != NULL);

    if (G_UNLIKELY(g_queue_is_empty(req->infs))) {
        if (req->func != NULL)
            req->func(req, req->data);

        steam_api_req_free(req);
        return;
    }

    if (g_queue_is_empty(req->infr)) {
        g_queue_free(req->infr);
        req->infr = g_queue_copy(req->infs);
    }

    info = g_queue_peek_head(req->infr);

    if (G_UNLIKELY(info->profile == NULL)) {
        if (req->func != NULL) {
            req->func(req, req->data);
        }

        steam_api_req_free(req);
        return;
    }

    srl = steam_http_uri_join(info->profile, "ajaxaliases", NULL);
    url_set(&url, srl);

    req->punc = steam_api_cb_user_info_nicks;
    steam_api_req_init(req, url.host, url.file);

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
    g_free(srl);
}

static void
steam_api_cb_user_remove(SteamApiReq *req, const json_value *json)
{
    if ((req->req->body_size < 1) || !bool2int(req->req->body)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to remove user");
        return;
    }

    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_user_remove(SteamApiReq *req, SteamId id)
{
    gchar sid[STEAM_ID_STRMAX];
    SteamUserInfo *info;

    g_return_if_fail(req != NULL);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_remove;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_REMOVE);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("steamid", sid),
        NULL
    );

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

static void
steam_api_cb_user_search(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    guint i;
    json_value *je;
    json_value *jv;
    SteamUserInfo *info;

    if (!steam_json_array_chk(json, "results", &jv)) {
        return;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "type", &str) ||
            (g_strcmp0(str, "user") != 0))
        {
            continue;
        }

        if (!steam_json_str_chk(je, "steamid", &str)) {
            continue;
        }

        info = steam_user_info_new(STEAM_ID_NEW_STR(str));
        str = steam_json_str(je, "matchingtext");
        info->nick = g_strdup(str);
        g_queue_push_tail(req->infs, info);
    }

    steam_api_cb_user_info_req(req, json);
}

void
steam_api_req_user_search(SteamApiReq *req, const gchar *name, guint count)
{
    gchar *snt;
    gchar *str;

    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_user_search;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIEND_SEARCH);

    snt = g_strdup_printf("%u", count);
    str = g_strdup_printf("\"%s\"", name);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("keywords", str),
        STEAM_HTTP_PAIR("count", snt),
        STEAM_HTTP_PAIR("offset", "0"),
        STEAM_HTTP_PAIR("fields", "all"),
        STEAM_HTTP_PAIR("targets", "users"),
        NULL
    );

    steam_http_req_send(req->req);

    g_free(snt);
    g_free(str);
}
