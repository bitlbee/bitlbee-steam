/*
 * Copyright 2012-2014 James Geboski <jgeboski@gmail.com>
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

/**
 * Gets the error domain for #SteamApi.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-api-error-quark");

    return q;
}

/**
 * Creates a new #SteamApi. The returned #SteamApi should be freed with
 * #steam_api_free() when no longer needed.
 *
 * @param umqid The umqid or NULL.
 *
 * @return The #SteamApi or NULL on error.
 **/
SteamApi *steam_api_new(const gchar *umqid)
{
    SteamApi *api;
    GRand    *rand;

    api = g_new0(SteamApi, 1);

    if (umqid == NULL) {
        rand       = g_rand_new();
        api->umqid = g_strdup_printf("%" G_GUINT32_FORMAT, g_rand_int(rand));

        g_rand_free(rand);
    } else {
        api->umqid = g_strdup(umqid);
    }

    api->info = steam_user_info_new(0);
    api->http = steam_http_new(STEAM_API_AGENT);
    api->msgs = g_queue_new();

    return api;
}

/**
 * Frees all memory used by a #SteamApi for authentication.
 *
 * @param api The #SteamApi.
 **/
void steam_api_free_auth(SteamApi *api)
{
    if (G_UNLIKELY(api == NULL))
        return;

    g_free(api->pktime);
    g_free(api->pkexp);
    g_free(api->pkmod);
    g_free(api->esid);
    g_free(api->cgid);

    api->pktime = NULL;
    api->pkexp  = NULL;
    api->pkmod  = NULL;
    api->esid   = NULL;
    api->cgid   = NULL;
}

/**
 * Frees all memory used by a #SteamApi.
 *
 * @param api The #SteamApi.
 **/
void steam_api_free(SteamApi *api)
{
    if (G_UNLIKELY(api == NULL))
        return;

    g_queue_free_full(api->msgs, (GDestroyNotify) steam_api_req_free);

    steam_http_free(api->http);
    steam_user_info_free(api->info);
    steam_api_free_auth(api);

    g_free(api->sessid);
    g_free(api->token);
    g_free(api->umqid);
    g_free(api);
}

/**
 * Gets the captcha URL of a captcha GID. The returned string should
 * be freed with #g_free() when no longer needed.
 *
 * @param cgid The captcha GID.
 *
 * @return The captcha URL, or NULL on error.
 **/
gchar *steam_api_captcha_url(const gchar *cgid)
{
    g_return_val_if_fail(cgid != NULL, NULL);

    return g_strdup_printf("https://%s%s?gid=%s", STEAM_COM_HOST,
                           STEAM_COM_PATH_CAPTCHA, cgid);
}

/**
 * Refreshes the #SteamApi after the modification of session
 * information.
 *
 * @param api The #SteamApi.
 **/
void steam_api_refresh(SteamApi *api)
{
    gchar *str;

    g_return_if_fail(api != NULL);

    str = g_strdup_printf("%" STEAM_ID_FORMAT "||oauth:%s", api->info->id,
                          api->token);

    steam_http_cookies_set(api->http,
        STEAM_HTTP_PAIR("steamLogin", str),
        STEAM_HTTP_PAIR("sessionid",  api->sessid),
        NULL
    );

    g_free(str);
}

/**
 * Parses and assigns #GError values from a #json_value.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value.
 *
 * @return TRUE if an error exists, otherwise FALSE.
 **/
static void steam_api_json_error(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gboolean     bool;
    gint64       in;
    guint        errc;

    if (steam_json_str_chk(json, "error", &str)) {
        if (g_ascii_strcasecmp(str, "OK") == 0)
            return;

        if (g_ascii_strcasecmp(str, "Timeout") == 0)
            return;

        if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
            req->api->online = FALSE;

            errc = STEAM_API_ERROR_EXPRIED;
            str  = "Session expired";
        } else {
            errc = STEAM_API_ERROR_GENERAL;
        }

        g_set_error(&req->err, STEAM_API_ERROR, errc, "%s", str);
        return;
    }

    if (steam_json_bool_chk(json, "success", &bool) && !bool) {
        if (steam_json_bool_chk(json, "captcha_needed", &bool) && bool)
            return;

        if (steam_json_bool_chk(json, "emailauth_needed", &bool) && bool)
            return;

        if (!steam_json_str_chk(json, "message", &str))
            str = "Unknown error";

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

/**
 * Parses and assigns #SteamUserInfo values from a #json_value.
 *
 * @param info The #SteamUserInfo.
 * @param json The #json_value.
 **/
static void steam_api_json_user_info(SteamUserInfo *info,
                                     const json_value *json)
{
    const gchar *str;
    const gchar *tmp;
    gint64       in;

    if (steam_json_str_chk(json, "gameextrainfo", &str)) {
        g_free(info->game);

        if (steam_json_str_chk(json, "gameid", &tmp))
            info->game = g_strdup(str);
        else
            info->game = g_strdup_printf("Non-Steam: %s", str);
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

    if (steam_json_int_chk(json, "lastlogoff", &in))
        info->ltime = in;

    if (steam_json_int_chk(json, "personastate", &in))
        info->state = in;

    if (steam_json_int_chk(json, "personastateflags", &in))
        info->flags = in;
}

/**
 * Parses and assigns #SteamUserInfo values from a #json_value.
 *
 * @param info The #SteamUserInfo.
 * @param json The #json_value.
 **/
static void steam_api_json_user_info_js(SteamUserInfo *info,
                                        const json_value *json)
{
    const gchar *str;
    const gchar *tmp;
    gint64       in;

    if (steam_json_str_chk(json, "m_strInGameName", &str)) {
        g_free(info->game);

        if (steam_json_str_chk(json, "m_nInGameAppID", &tmp))
            info->game = g_strdup(str);
        else
            info->game = g_strdup_printf("Non-Steam: %s", str);

        strip_html(info->game);
    }

    if (steam_json_str_chk(json, "m_strName", &str)) {
        g_free(info->nick);
        info->nick = g_strdup(str);
        strip_html(info->nick);
    }

    if (steam_json_int_chk(json, "m_ePersonaState", &in))
        info->state = in;

    if (steam_json_int_chk(json, "m_tsLastMessage", &in))
        info->mtime = in;

    if (steam_json_int_chk(json, "m_tsLastView", &in))
        info->vtime = in;
}

/**
 * Creates a new #SteamApiReq. The returned #SteamApiReq should be freed
 * with #steam_api_req_free() when no longer needed.
 *
 * @param api  The #SteamApi.
 * @param func The #SteamApiFunc or NULL.
 * @param data The user defined data or NULL.
 *
 * @return The #SteamApiReq or NULL on error.
 **/
SteamApiReq *steam_api_req_new(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_val_if_fail(api != NULL, NULL);

    req = g_new0(SteamApiReq, 1);

    req->api  = api;
    req->func = func;
    req->data = data;
    req->msgs = g_queue_new();
    req->infs = g_queue_new();
    req->infr = g_queue_new();

    return req;
}

/**
 * Creates a new forwarded #SteamApiReq. This NULLs the err, func, data,
 * msgs, infs, and infr data fields in the source #SteamApiReq, and
 * forwards them to the return #SteamApiReq. The returned #SteamApiReq
 * should be free with #steam_api_req_free() when no longer needed.
 *
 * @param req The #SteamApiReq.
 **/
SteamApiReq *steam_api_req_fwd(SteamApiReq *req)
{
    SteamApiReq *deq;

    g_return_val_if_fail(req != NULL, NULL);

    deq = g_memdup(req, sizeof *req);

    deq->flags = 0;
    deq->req   = NULL;
    deq->punc  = NULL;

    req->err   = NULL;
    req->func  = NULL;
    req->data  = NULL;
    req->msgs  = g_queue_new();
    req->infs  = g_queue_new();
    req->infr  = g_queue_new();

    return deq;
}

/**
 * Frees all memory used by a #SteamApiReq.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_free(SteamApiReq *req)
{
    GHashTable *tbl;
    GList      *l;
    GList      *n;

    if (G_UNLIKELY(req == NULL))
        return;

    tbl = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (l = req->msgs->head; l != NULL; l = l->next)
        g_hash_table_add(tbl, ((SteamUserMsg*) l->data)->info);

    for (l = req->infs->head; l != NULL; l = n) {
        n = l->next;

        if (g_hash_table_contains(tbl, l->data))
            g_queue_delete_link(req->infs, l);
    }

    g_queue_free_full(req->infs, (GDestroyNotify) steam_user_info_free);
    g_queue_free_full(req->msgs, (GDestroyNotify) steam_user_msg_free);

    g_queue_free(req->infr);
    g_hash_table_destroy(tbl);

    if (req->err != NULL)
        g_error_free(req->err);

    g_free(req);
}

/**
 * Implemented #SteamHttpFunc for handling #SteamApiReq replies.
 *
 * @param heq  The #SteamHttpReq.
 * @param data The user defined data, which is #SteamApiReq.
 **/
static void steam_api_req_cb(SteamHttpReq *heq, gpointer data)
{
    SteamApiReq *req = data;
    json_value  *json;

    req->req = heq;
    json     = NULL;

    if (G_LIKELY(req->err == NULL)) {
        if (heq->err != NULL) {
            g_propagate_error(&req->err, heq->err);
            heq->err = NULL;
        }

        if (!(req->flags & STEAM_API_REQ_FLAG_NOJSON) && (req->err == NULL)) {
            json = steam_json_new(heq->body, heq->body_size, &req->err);

            if (req->err == NULL)
                steam_api_json_error(req, json);
        }

        if ((req->punc != NULL) && (req->err == NULL))
            req->punc(req, json);

        if (json != NULL)
            json_value_free(json);
    }

    if (req->func != NULL) {
        g_queue_remove(req->infs, req->api->info);
        req->func(req, req->data);
    }

    steam_api_req_free(req);
}

/**
 * Initializes a new SSL based #SteamHttpReq for a #SteamApiReq.
 *
 * @param req  The #SteamApiReq.
 * @param host The request hostname.
 * @param path The request pathname.
 **/
void steam_api_req_init(SteamApiReq *req, const gchar *host, const gchar *path)
{
    SteamApi     *api = req->api;
    SteamHttpReq *heq;

    g_return_if_fail(req  != NULL);
    g_return_if_fail(api  != NULL);
    g_return_if_fail(host != NULL);
    g_return_if_fail(path != NULL);

    heq = steam_http_req_new(api->http, host, 443, path, steam_api_req_cb, req);

    heq->flags = STEAM_HTTP_REQ_FLAG_SSL;
    req->req   = heq;
}

/**
 * Implemented #SteamApiParser for requesting user info.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_info_req(SteamApiReq *req, const json_value *json)
{
    req = steam_api_req_fwd(req);
    steam_api_req_user_info(req);
}

/**
 * Implemented #SteamApiParser for #steam_api_cb_auth_rdir().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_auth_finish(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    steam_http_cookies_parse_req(req->api->http, req->req);
    str = g_hash_table_lookup(req->api->http->cookies, "sessionid");

    if (str == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to obtain sessionid");
        return;
    }

    g_free(req->api->sessid);
    req->api->sessid = g_strdup(str);
}

/**
 * Implemented #SteamApiParser for #steam_api_cb_auth().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_auth_rdir(SteamApiReq *req, const json_value *json)
{
    req = steam_api_req_fwd(req);
    req->punc = steam_api_cb_auth_finish;
    steam_api_req_init(req, STEAM_COM_HOST, "/");

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_auth().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_auth(SteamApiReq *req, const json_value *json)
{
    json_value  *jp;
    json_value  *jv;
    const gchar *str;
    gchar       *val;
    gboolean     bool;
    guint        errc;
    guint        i;

    if (steam_json_bool_chk(json, "success", &bool) && !bool) {
        if (steam_json_bool_chk(json, "emailauth_needed", &bool) && bool) {
            errc = STEAM_API_ERROR_STEAMGUARD;
            str  = steam_json_str(json, "emailsteamid");

            g_free(req->api->esid);
            req->api->esid = g_strdup(str);
        } else if (steam_json_bool_chk(json, "captcha_needed", &bool) && bool) {
            errc = STEAM_API_ERROR_CAPTCHA;
            str  = steam_json_str(json, "captcha_gid");

            g_free(req->api->cgid);
            req->api->cgid = g_strdup(str);
        } else {
            errc = STEAM_API_ERROR_UNKNOWN;
        }

        if (G_LIKELY(errc != STEAM_API_ERROR_UNKNOWN)) {
            str = steam_json_str(json, "message");
            g_set_error(&req->err, STEAM_API_ERROR, errc, "%s", str);
            return;
        }
    }

    if (!steam_json_val_chk(json, "oauth", json_string, &jv)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to obtain OAuth data");
        return;
    }

    jp = steam_json_new(jv->u.string.ptr, jv->u.string.length, &req->err);

    if ((jp == NULL) || (req->err != NULL))
        return;

    if (steam_json_str_chk(jp, "oauth_token", &str)) {
        g_free(req->api->token);
        req->api->token = g_strdup(str);
    }

    req = steam_api_req_fwd(req);
    req->punc = steam_api_cb_auth_rdir;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH_RDIR);

    for (i = 0; i < jp->u.object.length; i++) {
        str = jp->u.object.values[i].name;
        jv  = jp->u.object.values[i].value;
        val = steam_json_valstr(jv);

        steam_http_req_params_set(req->req, STEAM_HTTP_PAIR(str, val), NULL);
        g_free(val);
    }

    req->flags      |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    json_value_free(jp);
}

/**
 * Sends a authorization request. This is typically called twice to
 * complete the authorization process. First, the user is authenticated
 * partially, and then the Steam Guard code is requested. Then, with the
 * Steam Guard code, the authentication process can be completed.
 *
 * @param req      The #SteamApiReq.
 * @param user     The username.
 * @param pass     The password.
 * @param authcode The authorization code (Steam Guard) or NULL.
 * @param captcha  The captcha code or NULL.
 **/
void steam_api_req_auth(SteamApiReq *req, const gchar *user, const gchar *pass,
                        const gchar *authcode, const gchar *captcha)
{
    GTimeVal  tv;
    gchar    *pswd;
    gchar    *ms;

    g_return_if_fail(req  != NULL);
    g_return_if_fail(user != NULL);
    g_return_if_fail(pass != NULL);

    pswd = steam_crypt_rsa_enc_str(req->api->pkmod, req->api->pkexp, pass);

    if (pswd == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to encrypt password");

        if (req->func != NULL)
            req->func(req, req->data);

        steam_api_req_free(req);
        return;
    }

    req->punc = steam_api_cb_auth;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("username",        user),
        STEAM_HTTP_PAIR("password",        pswd),
        STEAM_HTTP_PAIR("emailauth",       authcode),
        STEAM_HTTP_PAIR("emailsteamid",    req->api->esid),
        STEAM_HTTP_PAIR("captchagid",      req->api->cgid),
        STEAM_HTTP_PAIR("captcha_text",    captcha),
        STEAM_HTTP_PAIR("rsatimestamp",    req->api->pktime),
        STEAM_HTTP_PAIR("oauth_client_id", STEAM_API_CLIENTID),
        STEAM_HTTP_PAIR("donotcache",      ms),
        STEAM_HTTP_PAIR("remember_login",  "true"),
        STEAM_HTTP_PAIR("oauth_scope",     "read_profile write_profile "
                                           "read_client write_client"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(pswd);
    g_free(ms);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_friends().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_friends(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    SteamUserRel   rel;
    json_value    *jv;
    json_value    *je;
    const gchar   *str;
    guint          i;

    if (!steam_json_array_chk(json, "friends", &jv))
        return;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "relationship", &str))
            continue;

        if (g_ascii_strcasecmp(str, "friend") == 0)
            rel = STEAM_USER_REL_FRIEND;
        else if (g_ascii_strcasecmp(str, "ignoredfriend") == 0)
            rel = STEAM_USER_REL_IGNORE;
        else
            continue;

        if (!steam_json_str_chk(je, "steamid", &str))
            continue;

        info = steam_user_info_new(STEAM_ID_NEW_STR(str));
        info->rel = rel;

        g_queue_push_tail(req->infs, info);
    }

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a friend list request. This returns the entire list of friends
 * for the #SteamApi user, including ignored friends.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_friends(SteamApiReq *req)
{
    gchar sid[STEAM_ID_STR_MAX];

    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_friends;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIENDS);
    STEAM_ID_STR(req->api->info->id, sid);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamid",      sid),
        STEAM_HTTP_PAIR("relationship", "friend,ignoredfriend"),
        NULL
    );

    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_key().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_key(SteamApiReq *req, const json_value *json)
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

/**
 * Sends a key request. The PKCS key is used to encrypt the password
 * before it is sent during the authentication phase.
 *
 * @param req  The #SteamApiReq.
 * @param user The username.
 **/
void steam_api_req_key(SteamApiReq *req, const gchar *user)
{
    GTimeVal  tv;
    gchar    *ms;

    g_return_if_fail(req  != NULL);
    g_return_if_fail(user != NULL);

    req->punc = steam_api_cb_key;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_KEY);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("username",   user),
        STEAM_HTTP_PAIR("donotcache", ms),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
    g_free(ms);
}

/**
 * Sends a logoff request. This simply logs the #SteamApi user off.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_logoff(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGOFF);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid",        req->api->umqid),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_logon().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_logon(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (steam_json_str_chk(json, "steamid", &str)) {
        req->api->info->id = STEAM_ID_NEW_STR(str);
        steam_api_refresh(req->api);
        g_queue_push_tail(req->infs, req->api->info);
    }

    if (steam_json_str_chk(json, "umqid", &str)) {
        g_free(req->api->umqid);
        req->api->umqid = g_strdup(str);
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

    steam_api_refresh(req->api);
    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a logon request. This simply logs the #SteamApi user on. The
 * #SteamApi user must be authenticated via #steam_api_req_auth()
 * before they can logon.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_logon(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_logon;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid",        req->api->umqid),
        STEAM_HTTP_PAIR("ui_mode",      "web"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_msg().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_msg(SteamApiReq *req, const json_value *json)
{
    if (!g_queue_is_empty(req->api->msgs)) {
        req = g_queue_pop_head(req->api->msgs);
        steam_http_req_send(req->req);
    }
}

/**
 * Sends a message request. This sends a #SteamUserMsg to a Steam user.
 *
 * @param req The #SteamApiReq.
 * @param msg The #SteamUserMsg.
 **/
void steam_api_req_msg(SteamApiReq *req, const SteamUserMsg *msg)
{
    const gchar *type;
    gchar        sid[STEAM_ID_STR_MAX];

    g_return_if_fail(req != NULL);
    g_return_if_fail(msg != NULL);

    req->punc = steam_api_cb_msg;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGE);

    STEAM_ID_STR(msg->info->id, sid);
    type = steam_user_msg_type_str(msg->type);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid",        req->api->umqid),
        STEAM_HTTP_PAIR("steamid_dst",  sid),
        STEAM_HTTP_PAIR("type",         type),
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

    if (g_queue_is_empty(req->api->msgs) && req->api->online)
        steam_http_req_send(req->req);
    else
        g_queue_push_tail(req->api->msgs, req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_poll().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_poll(SteamApiReq *req, const json_value *json)
{
    SteamUserMsg *msg;
    json_value   *jv;
    json_value   *je;
    const gchar  *str;
    SteamId       id;
    gboolean      selfie;
    gint64        in;
    guint         i;

    if (!steam_json_int_chk(json, "messagelast", &in) || (in == req->api->lmid))
        return;

    req->api->lmid = in;
    selfie = FALSE;

    if (!steam_json_array_chk(json, "messages", &jv))
        return;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "steamid_from", &str))
            continue;

        id = STEAM_ID_NEW_STR(str);

        if (id == req->api->info->id) {
            selfie = TRUE;
            continue;
        }

        /* For now, only handle individuals */
        if (STEAM_ID_TYPE(id) != STEAM_ID_TYPE_INDIVIDUAL)
            continue;

        msg = steam_user_msg_new(id);
        str = steam_json_str(je, "type");

        msg->type = steam_user_msg_type_from_str(str);
        msg->time = steam_json_int(je, "utc_timestamp");

        switch (msg->type) {
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

    if (selfie)
        g_queue_push_tail(req->infs, req->api->info);

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a poll request. This retrieves new messages from Steam. In
 * addition, this keeps the #SteamApi session active, and must be
 * called every 30 seconds.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_poll(SteamApiReq *req)
{
    const gchar *idle;
    gchar       *lmid;
    gchar       *tout;

    g_return_if_fail(req != NULL);

    static const SteamUtilEnum enums[] = {
        {STEAM_USER_STATE_AWAY,   G_STRINGIFY(STEAM_API_IDLEOUT_AWAY)},
        {STEAM_USER_STATE_SNOOZE, G_STRINGIFY(STEAM_API_IDLEOUT_SNOOZE)},
        STEAM_UTIL_ENUM_NULL
    };

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
        STEAM_HTTP_PAIR("umqid",        req->api->umqid),
        STEAM_HTTP_PAIR("message",      lmid),
        STEAM_HTTP_PAIR("sectimeout",   tout),
        STEAM_HTTP_PAIR("secidletime",  idle),
        NULL
    );

    req->req->timeout  = (STEAM_API_TIMEOUT + 5) * 1000;
    req->req->flags   |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(tout);
    g_free(lmid);
}

/**
 * Sends a friend accept request. If someone has requested friendship
 * with the #SteamApi user, this will accept the friendship request.
 *
 * @param req  The #SteamApiReq.
 * @param id   The #SteamId.
 * @param type The #SteamApiAcceptType.
 **/
void steam_api_req_user_accept(SteamApiReq *req, SteamId id,
                               SteamApiAcceptType type)
{
    SteamUserInfo *info;
    const gchar   *sct;
    gchar         *srl;
    url_t          url;
    gchar          sid[STEAM_ID_STR_MAX];

    static const SteamUtilEnum enums[] = {
        {STEAM_API_ACCEPT_TYPE_DEFAULT, "accept"},
        {STEAM_API_ACCEPT_TYPE_BLOCK,   "block"},
        {STEAM_API_ACCEPT_TYPE_IGNORE,  "ignore"},
        STEAM_UTIL_ENUM_NULL
    };

    g_return_if_fail(req != NULL);

    sct = steam_util_enum_ptr(enums, NULL, type);
    srl = g_strconcat(req->api->info->profile, "/home_process/", NULL);
    url_set(&url, srl);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_info_req;
    steam_api_req_init(req, url.host, url.file);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("id",        sid),
        STEAM_HTTP_PAIR("perform",   sct),
        STEAM_HTTP_PAIR("action",    "approvePending"),
        STEAM_HTTP_PAIR("itype",     "friend"),
        STEAM_HTTP_PAIR("json",      "1"),
        STEAM_HTTP_PAIR("xml",       "0"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(srl);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_add().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_add(SteamApiReq *req, const json_value *json)
{
    gint64 in;

    if (!steam_json_int_chk(json, "success", &in) || (in == 0)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to add friend");
        return;
    }

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a friend add request. This will request the friendship of
 * another Steam user. The Steam user is not really a friend until
 * they accept the request on their end.
 *
 * @param req The #SteamApiReq.
 * @param id  The #SteamId.
 **/
void steam_api_req_user_add(SteamApiReq *req, SteamId id)
{
    SteamUserInfo *info;
    gchar          sid[STEAM_ID_STR_MAX];

    g_return_if_fail(req != NULL);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_add;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_ADD);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID",     req->api->sessid),
        STEAM_HTTP_PAIR("steamid",       sid),
        STEAM_HTTP_PAIR("accept_invite", "0"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_chatlog().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_chatlog(SteamApiReq *req, const json_value *json)
{
    SteamUserMsg *msg;
    json_value   *jv;
    const gchar  *str;
    SteamId       id;
    gint32        aid;
    gint64        in;
    gsize         i;

    aid = STEAM_ID_ACCID(req->api->info->id);

    for (i = 0; i < json->u.array.length; i++) {
        jv = json->u.array.values[i];

        if (!steam_json_int_chk(jv, "m_unAccountID", &in) || (in == aid))
            continue;

        id = STEAM_ID_NEW(STEAM_ID_UNIV_PUBLIC, STEAM_ID_TYPE_INDIVIDUAL,
                          STEAM_ID_INST_DESKTOP, in);

        msg = steam_user_msg_new(id);
        msg->type = STEAM_USER_MSG_TYPE_SAYTEXT;
        msg->time = steam_json_int(jv, "m_tsTimestamp");

        str = steam_json_str(jv, "m_strMessage");
        msg->text = g_strdup(str);

        g_queue_push_tail(req->msgs, msg);
        g_queue_push_tail(req->infs, msg->info);
    }

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a chatlog request. This will retrieve read and unread messages
 * from the Steam user. If there are unread messages, this will mark
 * them as read.
 *
 * @param req The #SteamApiReq.
 * @param id  The #SteamId.
 **/
void steam_api_req_user_chatlog(SteamApiReq *req, SteamId id)
{
    gchar   *path;
    guint32  aid;

    g_return_if_fail(req != NULL);

    aid  = STEAM_ID_ACCID(id);
    path = g_strdup_printf("%s%" G_GINT32_FORMAT, STEAM_COM_PATH_CHATLOG, aid);

    req->punc = steam_api_cb_user_chatlog;
    steam_api_req_init(req, STEAM_COM_HOST, path);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionid", req->api->sessid),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(path);
}

/**
 * Sends a friend ignore request. This will either ignore or unignore
 * a Steam user from the #SteamApi user.
 *
 * @param req    The #SteamApiReq.
 * @param id     The #SteamId.
 * @param ignore TRUE to ignore, or FALSE to unignore.
 **/
void steam_api_req_user_ignore(SteamApiReq *req, SteamId id, gboolean ignore)
{
    SteamUserInfo *info;
    const gchar   *act;
    gchar         *user;
    gchar         *srl;
    url_t          url;

    g_return_if_fail(req != NULL);

    act  = ignore ? "ignore" : "unignore";
    user = g_strdup_printf("friends[%" STEAM_ID_FORMAT "]", id);
    srl  = g_strconcat(req->api->info->profile, "/friends/", NULL);
    url_set(&url, srl);

    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_info_req;
    steam_api_req_init(req, url.host, url.file);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("action",    act),
        STEAM_HTTP_PAIR(user,        "1"),
        NULL
    );

    req->flags      |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(srl);
    g_free(user);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_info().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_info(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    GHashTable    *ght;
    json_value    *jv;
    json_value    *je;
    const gchar   *str;
    GList         *l;
    GList         *n;
    gpointer       key;
    SteamId        id;
    guint          i;

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
            id  = STEAM_ID_NEW_STR(str);
            key = g_memdup(&id, sizeof id);
            g_hash_table_replace(ght, key, je);
        }
    }

    for (l = req->infr->head; l != NULL; l = n) {
        info = l->data;
        n    = l->next;
        je   = g_hash_table_lookup(ght, &info->id);

        if (je != NULL) {
            steam_api_json_user_info(info, je);
            g_queue_delete_link(req->infr, l);
        }
    }

    g_hash_table_destroy(ght);
    req = steam_api_req_fwd(req);

    if (!g_queue_is_empty(req->infr))
        steam_api_req_user_info(req);
    else
        steam_api_req_user_info_extra(req);
}

/**
 * Sends a user information request. This retrieves the user information
 * for all users in the #SteamApiReq->infos list.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_user_info(SteamApiReq *req)
{
    SteamUserInfo *info;
    GHashTable    *ght;
    GString       *gstr;
    GList         *l;
    GList         *n;
    gsize          i;

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

    ght  = g_hash_table_new(g_int64_hash, g_int64_equal);
    gstr = g_string_sized_new(2048);

    for (l = req->infr->head, i = 0; l != NULL; l = n) {
        info = l->data;
        n    = l->next;

        if (!g_hash_table_contains(ght, &info->id)) {
            g_hash_table_add(ght, &info->id);
            g_string_append_printf(gstr, "%" STEAM_ID_FORMAT ",", info->id);

            if ((++i % 100) == 0)
                break;
        }
    }

    /* Remove trailing comma */
    gstr->str[gstr->len - 1] = 0;

    req->punc = steam_api_cb_user_info;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamids",     gstr->str),
        NULL
    );

    steam_http_req_send(req->req);

    g_string_free(gstr, TRUE);
    g_hash_table_destroy(ght);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_info_extra().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_info_extra(SteamApiReq *req,
                                         const json_value *json)
{
    SteamUserInfo *info;
    GHashTable    *ght;
    json_value    *jp;
    json_value    *jv;
    json_value    *je;
    const gchar   *str;
    const gchar   *end;
    gchar         *jraw;
    GList         *l;
    gsize          size;
    gint64         aid;
    guint          i;

    str = strstr(req->req->body, "CWebChat");
    str = steam_util_ustrchr(str, '}');

    str = steam_util_ustrchr(str, '[');
    end = steam_util_ustrchr(str, ']');

    if ((str == NULL) || (end == NULL)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to obtain extra user information");
        return;
    }

    size = (end - str) + 1;
    jraw = g_strndup(str, size);
    jp   = steam_json_new(jraw, size, &req->err);

    g_free(jraw);

    if ((jp == NULL) || (req->err != NULL))
        return;

    ght = g_hash_table_new(g_int64_hash, g_int64_equal);

    for (i = 0; i < jp->u.array.length; i++) {
        je = jp->u.array.values[i];

        if (steam_json_val_chk(je, "m_unAccountID", json_integer, &jv))
            g_hash_table_replace(ght, &jv->u.integer, je);
    }

    for (l = req->infs->head; l != NULL; l = l->next) {
        info = l->data;
        aid  = STEAM_ID_ACCID(info->id);
        je   = g_hash_table_lookup(ght, &aid);

        if (je != NULL)
            steam_api_json_user_info_js(info, je);
    }

    g_hash_table_destroy(ght);
    json_value_free(jp);
}

/**
 * Sends a user information request for extra information. This gets
 * additional information for the friends of the #SteamApi user.
 * Information such as last message times, which can be used with
 * #steam_api_req_chatlog() for displaying unread messages.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_user_info_extra(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_user_info_extra;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_CHAT);

    req->flags |= STEAM_API_REQ_FLAG_NOJSON;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_info_nicks().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_info_nicks(SteamApiReq *req,
                                         const json_value *json)
{
    SteamUserInfo *info;
    json_value    *je;
    const gchar   *str;
    guint          i;

    info = g_queue_pop_head(req->infr);

    for (i = 0; i < json->u.array.length; i++) {
        je = json->u.array.values[i];

        if (!steam_json_str_chk(je, "newname", &str))
            continue;

        if (g_strcmp0(str, info->nick) != 0)
            info->nicks = g_slist_prepend(info->nicks, g_strdup(str));
    }

    info->nicks = g_slist_reverse(info->nicks);

    if (!g_queue_is_empty(req->infr)) {
        req = steam_api_req_fwd(req);
        steam_api_req_user_info_nicks(req);
    }
}

/**
 * Sends a user nickname information request. This retrieves the user
 * nicname information for all users in the #SteamApiReq->infos list.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_user_info_nicks(SteamApiReq *req)
{
    SteamUserInfo *info;
    gchar         *srl;
    url_t          url;

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
    srl  = g_strconcat(info->profile, "/ajaxaliases/", NULL);

    url_set(&url, srl);

    req->punc = steam_api_cb_user_info_nicks;
    steam_api_req_init(req, url.host, url.file);

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(srl);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_remove().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_remove(SteamApiReq *req, const json_value *json)
{
    if ((req->req->body_size < 1) || !bool2int(req->req->body)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_GENERAL,
                    "Failed to remove user");
        return;
    }

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a friend remove request. This will remove a Steam friend from
 * the friend list of the #SteamApi user. This does not block the user,
 * see: #steam_api_req_user_ignore().
 *
 * @param req The #SteamApiReq.
 * @param id  The #SteamId.
 **/
void steam_api_req_user_remove(SteamApiReq *req, SteamId id)
{
    SteamUserInfo *info;
    gchar          sid[STEAM_ID_STR_MAX];

    g_return_if_fail(req != NULL);

    STEAM_ID_STR(id, sid);
    info = steam_user_info_new(id);
    g_queue_push_head(req->infs, info);

    req->punc = steam_api_cb_user_remove;
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_REMOVE);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", req->api->sessid),
        STEAM_HTTP_PAIR("steamid",   sid),
        NULL
    );

    req->flags      |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Implemented #SteamApiParser for #steam_api_req_user_search().
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_cb_user_search(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    json_value    *jv;
    json_value    *je;
    const gchar   *str;
    guint          i;

    if (!steam_json_array_chk(json, "results", &jv))
        return;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str_chk(je, "type", &str) ||
            (g_strcmp0(str, "user") != 0))
        {
            continue;
        }

        if (!steam_json_str_chk(je, "steamid", &str))
            continue;

        info = steam_user_info_new(STEAM_ID_NEW_STR(str));

        str = steam_json_str(je, "matchingtext");
        info->nick = g_strdup(str);

        g_queue_push_tail(req->infs, info);
    }

    steam_api_cb_user_info_req(req, json);
}

/**
 * Sends a user search request. This searches for Steam users based on
 * a search term. This is very useful when attempting to add Steam
 * users by their name via #steam_api_req_user_add().
 *
 * @param req   The #SteamApiReq.
 * @param name  The username.
 * @param count The amount of search results.
 **/
void steam_api_req_user_search(SteamApiReq *req, const gchar *name, guint count)
{
    gchar *snt;
    gchar *str;

    g_return_if_fail(req != NULL);

    req->punc = steam_api_cb_user_search;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIEND_SEARCH);

    snt = g_strdup_printf("%u",     count);
    str = g_strdup_printf("\"%s\"", name);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("keywords",     str),
        STEAM_HTTP_PAIR("count",        snt),
        STEAM_HTTP_PAIR("offset",       "0"),
        STEAM_HTTP_PAIR("fields",       "all"),
        STEAM_HTTP_PAIR("targets",      "users"),
        NULL
    );

    steam_http_req_send(req->req);

    g_free(snt);
    g_free(str);
}
