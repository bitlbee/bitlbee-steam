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

#include "steam-api.h"
#include "steam-http.h"
#include "steam-json.h"

static void steam_api_auth_rdir(SteamApiReq *req, GTree *params);
static void steam_api_friends_cinfo(SteamApiReq *req);
static void steam_api_relogon(SteamApiReq *req);
static void steam_api_summaries(SteamApiReq *req);

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

    api->id   = steam_user_id_new(0);
    api->http = steam_http_new(STEAM_API_AGENT);

    return api;
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

    steam_auth_free(api->auth);
    steam_http_free(api->http);
    steam_user_id_free(api->id);

    g_free(api->sessid);
    g_free(api->token);
    g_free(api->umqid);
    g_free(api);
}

/**
 * Gets the profile URL of a #SteamUserId. The returned string should
 * be freed with #g_free() when no longer needed.
 *
 * @param id The #SteamUserId.
 *
 * @return The profile URL, or NULL on error.
 **/
gchar *steam_api_profile_url(const SteamUserId *id)
{
    g_return_val_if_fail(id != NULL, NULL);

    return g_strdup_printf("https://%s%s%s/", STEAM_COM_HOST,
                           STEAM_COM_PATH_PROFILE, id->steam.s);
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

    str = g_strdup_printf("%s||oauth:%s", api->id->steam.s, api->token);

    steam_http_cookies_set(api->http,
        STEAM_HTTP_PAIR("steamLogin", str),
        STEAM_HTTP_PAIR("sessionid",  api->sessid),
        NULL
    );

    g_free(str);
}

/**
 * Creates a new #SteamApiReq. The returned #SteamApiReq should be freed
 * with #steam_api_req_free() when no longer needed.
 *
 * @param api  The #SteamApi.
 * @param type The #SteamApiReqType.
 * @param func The user callback function or NULL.
 * @param data The user defined data or NULL.
 *
 * @return The #SteamApiReq or NULL on error.
 **/
SteamApiReq *steam_api_req_new(SteamApi *api, SteamApiReqType type,
                               gpointer func, gpointer data)
{
    SteamApiReq *req;

    req = g_new0(SteamApiReq, 1);

    req->type = type;
    req->api  = api;
    req->func = func;
    req->data = data;

    return req;
}

/**
 * Frees all memory used by a #SteamApiReq.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_free(SteamApiReq *req)
{
    if (G_UNLIKELY(req == NULL))
        return;

    if ((req->rfunc != NULL) && (req->rdata != NULL))
        req->rfunc(req->rdata);

    if (req->infos != NULL)
        g_list_free(req->infos);

    if (req->err != NULL)
        g_error_free(req->err);

    g_free(req);
}

/**
 * Calls the user callback function.
 *
 * @param req The #SteamApiReq.
 **/
void steam_api_req_func(SteamApiReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->func == NULL)
        return;

    switch (req->type) {
    case STEAM_API_REQ_TYPE_AUTH:
    case STEAM_API_REQ_TYPE_KEY:
    case STEAM_API_REQ_TYPE_LOGOFF:
    case STEAM_API_REQ_TYPE_LOGON:
    case STEAM_API_REQ_TYPE_RELOGON:
    case STEAM_API_REQ_TYPE_MESSAGE:
        ((SteamApiFunc) req->func)(req->api, req->err, req->data);
        return;

    case STEAM_API_REQ_TYPE_FRIEND_ACCEPT:
    case STEAM_API_REQ_TYPE_FRIEND_ADD:
    case STEAM_API_REQ_TYPE_FRIEND_IGNORE:
    case STEAM_API_REQ_TYPE_FRIEND_REMOVE:
        ((SteamApiIdFunc) req->func)(req->api, req->rdata, req->err, req->data);
        return;

    case STEAM_API_REQ_TYPE_CHATLOG:
    case STEAM_API_REQ_TYPE_FRIEND_SEARCH:
    case STEAM_API_REQ_TYPE_FRIENDS:
    case STEAM_API_REQ_TYPE_POLL:
        ((SteamApiListFunc) req->func)(req->api, req->rdata, req->err,
                                       req->data);
        return;

    case STEAM_API_REQ_TYPE_SUMMARY:
        ((SteamApiInfoFunc) req->func)(req->api, req->rdata, req->err,
                                       req->data);
        return;

    default:
        return;
    }
}

/**
 * Gets the string representation of a #SteamApiReqType.
 *
 * @param type The #SteamApiReqType.
 *
 * @return The string representation of the #SteamApiReqType.
 **/
const gchar *steam_api_req_type_str(SteamApiReqType type)
{
    static const gchar *strs[STEAM_API_REQ_TYPE_LAST] = {
        [STEAM_API_REQ_TYPE_AUTH]          = "Authentication",
        [STEAM_API_REQ_TYPE_AUTH_RDIR]     = "Authentication (redirect)",
        [STEAM_API_REQ_TYPE_CHATLOG]       = "ChatLog",
        [STEAM_API_REQ_TYPE_FRIEND_ACCEPT] = "Friend Acceptance",
        [STEAM_API_REQ_TYPE_FRIEND_ADD]    = "Friend Addition",
        [STEAM_API_REQ_TYPE_FRIEND_IGNORE] = "Friend Ignore",
        [STEAM_API_REQ_TYPE_FRIEND_REMOVE] = "Friend Removal",
        [STEAM_API_REQ_TYPE_FRIEND_SEARCH] = "Friend Search",
        [STEAM_API_REQ_TYPE_FRIENDS]       = "Friends",
        [STEAM_API_REQ_TYPE_FRIENDS_CINFO] = "Friends Chat Info",
        [STEAM_API_REQ_TYPE_KEY]           = "Key",
        [STEAM_API_REQ_TYPE_LOGON]         = "Logon",
        [STEAM_API_REQ_TYPE_RELOGON]       = "Relogon",
        [STEAM_API_REQ_TYPE_LOGOFF]        = "Logoff",
        [STEAM_API_REQ_TYPE_MESSAGE]       = "Message",
        [STEAM_API_REQ_TYPE_POLL]          = "Polling",
        [STEAM_API_REQ_TYPE_SUMMARIES]     = "Summaries",
        [STEAM_API_REQ_TYPE_SUMMARY]       = "Summary"
    };

    if ((type <= STEAM_API_REQ_TYPE_NONE) || (type >= STEAM_API_REQ_TYPE_LAST))
        return "Generic";

    return strs[type];
}

/**
 * Parses and assigns #SteamUserInfo values from a #json_value.
 *
 * @param info The #SteamUserInfo.
 * @param json The #json_value.
 **/
static void steam_api_user_info_json(SteamUserInfo *info,
                                     const json_value *json)
{
    const gchar *str;
    gint64       in;

    steam_json_str(json, "gameextrainfo", &str);
    info->game = g_strdup(str);

    steam_json_str(json, "gameserverip", &str);
    info->server = g_strdup(str);

    steam_json_str(json, "personaname", &str);
    info->nick = g_strdup(str);

    steam_json_str(json, "realname", &str);
    info->fullname = g_strdup(str);

    steam_json_int(json, "personastate", &in);
    info->state = in;
}

/**
 * Implemented #SteamApiParseFunc for authentication replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_auth_cb(SteamApiReq *req, const json_value *json)
{
    SteamApiError  err;
    json_value    *jp;
    json_value    *jv;
    const gchar   *str;
    GTree         *prms;

    if (steam_json_str(json, "captcha_gid", &str))
        steam_auth_captcha(req->api->auth, str);

    if (steam_json_str(json, "emailsteamid", &str))
        steam_auth_email(req->api->auth, str);

    if (!steam_json_bool(json, "success")) {
        if (steam_json_bool(json, "emailauth_needed"))
            err = STEAM_API_ERROR_AUTH_GUARD;
        else if (steam_json_bool(json, "captcha_needed"))
            err = STEAM_API_ERROR_AUTH_CAPTCHA;
        else
            err = STEAM_API_ERROR_AUTH;

        if (!steam_json_str(json, "message", &str))
            str = "Failed to authenticate";

        g_set_error(&req->err, STEAM_API_ERROR, err, "%s", str);
        return;
    }

    if (!steam_json_val(json, "oauth", json_string, &jv)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth data");
        return;
    }

    jp = steam_json_new(jv->u.string.ptr, jv->u.string.length, &req->err);

    if ((jp == NULL) || (req->err != NULL))
        return;

    if (!steam_json_str(jp, "oauth_token", &str)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth token");
        goto finish;
    }

    g_free(req->api->token);
    req->api->token = g_strdup(str);

    prms = steam_json_tree(jp);
    steam_api_auth_rdir(req, prms);
    g_tree_destroy(prms);

finish:
    json_value_free(jp);
}

/**
 * Implemented #SteamApiParseFunc for authentication redirect replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_auth_rdir_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    steam_http_cookies_parse_req(req->api->http, req->req);
    str = g_tree_lookup(req->api->http->cookies, "sessionid");

    if (str == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth session ID");
        return;
    }

    g_free(req->api->sessid);
    req->api->sessid = g_strdup(str);
}

/**
 * Implemented #GDestroyNotify for #steam_api_chatlog_cb().
 *
 * @param results The #GSList of items, which are #SteamUserMsg.
 **/
static void steam_api_chatlog_free(GSList *messages)
{
    g_slist_free_full(messages, (GDestroyNotify) steam_user_msg_free);
}

/**
 * Implemented #SteamApiParseFunc for chatlog replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_chatlog_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserMsg *msg;
    json_value   *jv;
    GSList       *messages;
    const gchar  *str;
    gint64        in;
    gsize         i;

    messages = NULL;

    for (i = 0; i < json->u.array.length; i++) {
        jv = json->u.array.values[i];
        steam_json_int(jv, "m_unAccountID", &in);

        if (in == req->api->id->commu.i)
            continue;

        in = STEAM_USER_ID_NEW(STEAM_USER_ID_UNI_PUBLIC,
                               STEAM_USER_ID_TYPE_INDIVIDUAL,
                               1, in);

        msg = steam_user_msg_new(in);
        msg->type = STEAM_USER_MSG_TYPE_SAYTEXT;

        steam_json_str(jv, "m_strMessage",  &str);
        msg->text = g_strdup(str);

        steam_json_int(jv, "m_tsTimestamp", &in);
        msg->time = in;

        messages = g_slist_prepend(messages, msg);
    }

    req->rdata = g_slist_reverse(messages);
    req->rfunc = (GDestroyNotify) steam_api_chatlog_free;
}


/**
 * Implemented #SteamApiParseFunc for friend accept replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friend_accept_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (!steam_json_scmp(json, "error_text", "", &str))
        return;

    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_ACCEPT,
                "%s", str);
}

/**
 * Implemented #SteamApiParseFunc for friend add replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friend_add_cb(SteamApiReq *req, const json_value *json)
{
    json_value *jv;

    if (!steam_json_val(json, "failed_invites_result", json_array, &jv))
        return;

    if (jv->u.array.length < 1)
        return;

    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_ADD,
                "Failed to add friend");
}

/**
 * Implemented #SteamApiParseFunc for friend ignore replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friend_ignore_cb(SteamApiReq *req, const json_value *json)
{

}

/**
 * Implemented #SteamApiParseFunc for friend remove replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friend_remove_cb(SteamApiReq *req, const json_value *json)
{
    if ((req->req->body_size > 0) && bool2int(req->req->body))
        return;

    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_REMOVE,
                "Failed to remove friend");
}

/**
 * Implemented #GDestroyNotify for #steam_api_friend_search_cb().
 *
 * @param results The #GSList of items, which are #SteamUserInfo.
 **/
static void steam_api_friend_search_free(GSList *results)
{
    g_slist_free_full(results, (GDestroyNotify) steam_user_info_free);
}

/**
 * Implemented #SteamApiParseFunc for friend search replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friend_search_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    json_value    *jv;
    json_value    *je;
    GSList        *results;
    const gchar   *str;
    guint          i;

    if (!steam_json_val(json, "results", json_array, &jv))
        return;

    results = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_scmp(je, "type", "user", &str))
            continue;

        if (!steam_json_str(je, "steamid", &str))
            continue;

        info = steam_user_info_new_str(str);

        steam_json_str(je, "matchingtext", &str);
        info->nick = g_strdup(str);

        results = g_slist_prepend(results, info);
    }

    req->rdata = g_slist_reverse(results);
    req->rfunc = (GDestroyNotify) steam_api_friend_search_free;
}

/**
 * Implemented #GDestroyNotify for #steam_api_friends_cb().
 *
 * @param friends The #GSList of items, which are #SteamUserInfo.
 **/
static void steam_api_friends_free(GSList *friends)
{
    g_slist_free_full(friends, (GDestroyNotify) steam_user_info_free);
}

/**
 * Implemented #SteamApiParseFunc for friends list replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friends_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    SteamUserRel   rel;
    json_value    *jv;
    json_value    *je;
    GSList        *friends;
    const gchar   *str;
    guint          i;

    if (!steam_json_val(json, "friends", json_array, &jv))
        return;

    friends = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        steam_json_str(je, "relationship", &str);

        if (str == NULL)
            continue;

        if (g_ascii_strcasecmp(str, "friend") == 0)
            rel = STEAM_USER_REL_FRIEND;
        else if (g_ascii_strcasecmp(str, "ignoredfriend") == 0)
            rel = STEAM_USER_REL_IGNORE;
        else
            continue;

        if (!steam_json_str(je, "steamid", &str))
            continue;

        info = steam_user_info_new_str(str);
        info->rel = rel;

        friends    = g_slist_prepend(friends, info);
        req->infos = g_list_prepend(req->infos, info);
    }

    req->rdata = friends;
    req->rfunc = (GDestroyNotify) steam_api_friends_free;

    if (friends != NULL)
        steam_api_friends_cinfo(req);
}

/**
 * Find the occurrance of a character in a string not inside quotes.
 *
 * @param str The search string.
 * @param chr The character to find.
 *
 * @return A pointer to the character, or NULL if it was not found.
 **/
static const gchar *unquotechr(const gchar *str, gchar chr)
{
    gboolean quoted;
    gsize    size;
    gsize    cans;
    gsize    i;
    gssize   j;

    if (G_UNLIKELY(str == NULL))
        return NULL;

    size = strlen(str);

    for (quoted = FALSE, i = 0; i < size; i++) {
        if (!quoted && (str[i] == chr))
            return str + i;

        if (str[i] != '"')
            continue;

        for (cans = 0, j = i - 1; (j >= 0) && (str[j] == '\\'); j--, cans++);

        if ((cans % 2) == 0)
            quoted = !quoted;
    }

    return NULL;
}

/**
 * Implemented #SteamApiParseFunc for friends chat info replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_friends_cinfo_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    GHashTable    *stbl;
    json_value    *jp;
    json_value    *je;
    const gchar   *str;
    const gchar   *end;
    gchar         *jraw;
    gsize          size;
    GSList        *l;
    guint          i;

    str = strstr(req->req->body, "CWebChat");
    str = unquotechr(str, '}');

    str = unquotechr(str, '[');
    end = unquotechr(str, ']');

    if ((str == NULL) || (end == NULL)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIENDS_CINFO,
                    "Failed to obtain friends chat information");
        return;
    }

    size = (end - str) + 1;
    jraw = g_strndup(str, size);
    jp   = steam_json_new(jraw, size, &req->err);

    if ((jp == NULL) || (req->err != NULL)) {
        g_free(jraw);
        return;
    }

    stbl = g_hash_table_new(g_str_hash, g_str_equal);

    for (l = req->rdata; l != NULL; l = l->next) {
        info = l->data;
        g_hash_table_insert(stbl, info->id->steam.s, info);
    }

    for (i = 0; i < jp->u.array.length; i++) {
        je = jp->u.array.values[i];

        if (!steam_json_str(je, "m_ulSteamID", &str))
            continue;

        info = g_hash_table_lookup(stbl, str);

        if (info == NULL)
            continue;

        steam_json_int(je, "m_tsLastMessage", &info->mtime);
        steam_json_int(je, "m_tsLastView",    &info->vtime);
    }

    g_hash_table_destroy(stbl);
    json_value_free(jp);
    g_free(jraw);
}

/**
 * Implemented #SteamApiParseFunc for PKCS key replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_key_cb(SteamApiReq *req, const json_value *json)
{
    SteamAuth   *auth;
    const gchar *str;

    if (steam_json_scmp(json, "success", "false", &str))
        goto error;

    auth = (req->api->auth != NULL) ? req->api->auth : steam_auth_new();

    if (!steam_json_str(json, "publickey_mod", &str) ||
        !steam_auth_key_mod(auth, str))
        goto error;

    if (!steam_json_str(json, "publickey_exp", &str) ||
        !steam_auth_key_exp(auth, str))
        goto error;

    if (steam_json_str(json, "timestamp", &str))
        auth->time = g_strdup(str);

    req->api->auth = auth;
    return;

error:
    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_KEY,
                "Failed to retrieve authentication key");
}

/**
 * Implemented #SteamApiParseFunc for logon replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_logon_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;
    gint64       in;

    if (!steam_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON,
                    "%s", str);
        return;
    }

    steam_json_int(json, "message", &in);
    req->api->lmid = in;

    steam_json_int(json, "utc_timestamp", &in);
    req->api->time = in;

    if (!steam_json_scmp(json, "steamid", req->api->id->steam.s, &str)) {
        steam_user_id_free(req->api->id);
        req->api->id = steam_user_id_new_str(str);
    }

    if (!steam_json_scmp(json, "umqid", req->api->umqid, &str)) {
        g_free(req->api->umqid);
        req->api->umqid = g_strdup(str);
    }
}

/**
 * Implemented #SteamApiParseFunc for relogon replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_relogon_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    steam_http_queue_pause(req->api->http, FALSE);

    if (!steam_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_RELOGON,
                    "%s", str);
        return;
    }

    req->flags |= STEAM_API_REQ_FLAG_NOCALL | STEAM_API_REQ_FLAG_NOFREE;
}

/**
 * Implemented #SteamApiParseFunc for logoff replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_logoff_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

/**
 * Implemented #SteamApiParseFunc for message replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_message_cb(SteamApiReq *req, const json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
        steam_api_relogon(req);
        return;
    }

    g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

/**
 * Implemented #GDestroyNotify for #steam_api_poll_free().
 *
 * @param messages The #GSList of items, which are #SteamUserInfo.
 **/
static void steam_api_poll_free(GSList *messages)
{
    g_slist_free_full(messages, (GDestroyNotify) steam_user_msg_free);
}

/**
 * Implemented #SteamApiParseFunc for poll replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_poll_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserMsg    *msg;
    SteamUserIdType  type;
    json_value      *jv;
    json_value      *je;
    GSList          *messages;
    const gchar     *str;
    gint64           in;
    guint            i;

    if (!steam_json_scmp(json, "error", "OK", &str))
    {
        if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
            steam_api_relogon(req);
            return;
        }

        if (g_ascii_strcasecmp(str, "Timeout") != 0) {
            g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        "%s", str);
            return;
        }

        steam_json_int(json, "sectimeout", &in);

        if (in < STEAM_API_TIMEOUT) {
            g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        "Timeout of %" G_GINT64_FORMAT " too low", in);
            return;
        }
    }

    if (!steam_json_val(json, "messages", json_array, &jv) ||
        !steam_json_int(json, "messagelast", &in) ||
        (in == req->api->lmid))
    {
        return;
    }

    req->api->lmid = in;
    messages       = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (steam_json_scmp(je, "steamid_from", req->api->id->steam.s, &str))
            continue;

        in   = g_ascii_strtoll(str, NULL, 10);
        type = STEAM_USER_ID_TYPE(in);

        /* For now, only handle individuals */
        if (type != STEAM_USER_ID_TYPE_INDIVIDUAL)
            continue;

        msg = steam_user_msg_new_str(str);

        steam_json_str(je, "type", &str);
        steam_json_int(je, "utc_timestamp", &in);

        msg->type   = steam_user_msg_type_from_str(str);
        msg->time = in;

        switch (msg->type) {
        case STEAM_USER_MSG_TYPE_SAYTEXT:
        case STEAM_USER_MSG_TYPE_EMOTE:
            steam_json_str(je, "text", &str);
            msg->text = g_strdup(str);
            break;

        case STEAM_USER_MSG_TYPE_STATE:
            steam_json_str(je, "persona_name", &str);
            msg->info->nick = g_strdup(str);
            req->infos = g_list_prepend(req->infos, msg->info);
            break;

        case STEAM_USER_MSG_TYPE_RELATIONSHIP:
            steam_json_int(je, "persona_state", &in);
            msg->info->act = in;
            req->infos = g_list_prepend(req->infos, msg->info);
            break;

        case STEAM_USER_MSG_TYPE_TYPING:
        case STEAM_USER_MSG_TYPE_LEFT_CONV:
            break;

        default:
            steam_user_msg_free(msg);
            continue;
        }

        messages = g_slist_prepend(messages, msg);
    }

    req->rdata = g_slist_reverse(messages);
    req->rfunc = (GDestroyNotify) steam_api_poll_free;
}

/**
 * Implemented #SteamApiParseFunc for summaries replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_summaries_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    json_value    *jv;
    json_value    *je;
    const gchar   *str;
    GList         *l;
    GList         *c;
    guint          i;

    if ((!steam_json_val(json, "players", json_array, &jv) ||
         (jv->u.array.length < 1)) &&
        (req->infos != NULL))
    {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARIES,
                    "Failed to retrieve requested friend summaries");
        return;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str(je, "steamid", &str))
            continue;

        for (l = req->infos; l != NULL; ) {
            info = l->data;

            if (g_strcmp0(info->id->steam.s, str) != 0) {
                l = l->next;
                continue;
            }

            c = l;
            l = l->next;

            req->infos = g_list_delete_link(req->infos, c);
            steam_api_user_info_json(info, je);
        }
    }
}

/**
 * Implemented #SteamApiParseFunc for summary replies.
 *
 * @param req  The #SteamApiReq.
 * @param json The #json_value or NULL.
 **/
static void steam_api_summary_cb(SteamApiReq *req, const json_value *json)
{
    SteamUserInfo *info;
    json_value    *jv;
    const gchar   *str;

    if (!steam_json_val(json, "players", json_array, &jv) ||
        (jv->u.array.length != 1))
    {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARY,
                    "Failed to retrieve friend summary");
        return;
    }

    jv = jv->u.array.values[0];

    if (!steam_json_str(jv, "steamid", &str)) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARY,
                    "Failed to retrieve friend summary steamid");
        return;
    }

    info = steam_user_info_new_str(str);
    steam_api_user_info_json(info, jv);

    req->rdata = info;
    req->rfunc = (GDestroyNotify) steam_user_info_free;
}

/**
 * Implemented #SteamHttpFunc for handling #SteamApiReq replies.
 *
 * @param heq  The #SteamHttpReq.
 * @param data The user defined data, which is #SteamApiReq.
 **/
static void steam_api_cb(SteamHttpReq *heq, gpointer data)
{
    SteamApiReq     *req = data;
    SteamApiReq     *rec;
    SteamApiReqType  type;
    json_value      *json;

    static const SteamApiParseFunc pfuncs[STEAM_API_REQ_TYPE_LAST] = {
        [STEAM_API_REQ_TYPE_AUTH]          = steam_api_auth_cb,
        [STEAM_API_REQ_TYPE_AUTH_RDIR]     = steam_api_auth_rdir_cb,
        [STEAM_API_REQ_TYPE_CHATLOG]       = steam_api_chatlog_cb,
        [STEAM_API_REQ_TYPE_FRIEND_ACCEPT] = steam_api_friend_accept_cb,
        [STEAM_API_REQ_TYPE_FRIEND_ADD]    = steam_api_friend_add_cb,
        [STEAM_API_REQ_TYPE_FRIEND_IGNORE] = steam_api_friend_ignore_cb,
        [STEAM_API_REQ_TYPE_FRIEND_REMOVE] = steam_api_friend_remove_cb,
        [STEAM_API_REQ_TYPE_FRIEND_SEARCH] = steam_api_friend_search_cb,
        [STEAM_API_REQ_TYPE_FRIENDS]       = steam_api_friends_cb,
        [STEAM_API_REQ_TYPE_FRIENDS_CINFO] = steam_api_friends_cinfo_cb,
        [STEAM_API_REQ_TYPE_KEY]           = steam_api_key_cb,
        [STEAM_API_REQ_TYPE_LOGOFF]        = steam_api_logoff_cb,
        [STEAM_API_REQ_TYPE_LOGON]         = steam_api_logon_cb,
        [STEAM_API_REQ_TYPE_RELOGON]       = steam_api_relogon_cb,
        [STEAM_API_REQ_TYPE_MESSAGE]       = steam_api_message_cb,
        [STEAM_API_REQ_TYPE_POLL]          = steam_api_poll_cb,
        [STEAM_API_REQ_TYPE_SUMMARIES]     = steam_api_summaries_cb,
        [STEAM_API_REQ_TYPE_SUMMARY]       = steam_api_summary_cb
    };

    /* Ensure the active request is defined */
    req->req = heq;

    if (req->typel != STEAM_API_REQ_TYPE_NONE) {
        type = req->typel;
        req->typel = STEAM_API_REQ_TYPE_NONE;
    } else {
        type = req->type;
    }

    if ((type <= STEAM_API_REQ_TYPE_NONE) || (type >= STEAM_API_REQ_TYPE_LAST))
    {
        req->flags &= ~STEAM_HTTP_REQ_FLAG_NOFREE;
        steam_api_req_free(req);
        g_return_if_reached();
    }

    rec = g_memdup(req, sizeof (SteamApiReq));
    req->flags = 0;

    if (req->err != NULL) {
        g_propagate_error(&req->err, heq->err);
        heq->err = NULL;
    }

    if (req->err == NULL)
    {
        if (!(rec->flags & STEAM_API_REQ_FLAG_NOJSON)) {
            json = steam_json_new(heq->body, heq->body_size, &req->err);

            if (req->err == NULL)
                pfuncs[type](req, json);

            if (json != NULL)
                json_value_free(json);
        } else {
            pfuncs[type](req, NULL);
        }
    }

    if ((req->err == NULL) && (req->infos != NULL) && (req->type == rec->type))
        steam_api_summaries(req);

    if (req->type != rec->type) {
        req->typel = req->type;
        req->type  = rec->type;
    }

    if (!(req->flags & STEAM_API_REQ_FLAG_NOCALL)) {
        if (req->err != NULL)
            g_prefix_error(&req->err, "%s: ", steam_api_req_type_str(type));

        steam_api_req_func(req);
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_NOFREE)
        req->flags |= STEAM_API_REQ_FLAG_NOFREE;

    if (!(req->flags & STEAM_API_REQ_FLAG_NOFREE)) {
        req->req = NULL;
        steam_api_req_free(req);
    } else if (req->err != NULL) {
        g_error_free(req->err);
        req->err = NULL;
    }

    g_free(rec);
}

/**
 * Initializes a new SSL based #SteamHttpReq for a #SteamApiReq.
 *
 * @param req  The #SteamApiReq.
 * @param host The request hostname.
 * @param path The request pathname.
 **/
static void steam_api_req_init(SteamApiReq *req, const gchar *host,
                               const gchar *path)
{
    SteamApi     *api = req->api;
    SteamHttpReq *heq;

    heq = steam_http_req_new(api->http, host, 443, path, steam_api_cb, req);

    heq->flags = STEAM_HTTP_REQ_FLAG_SSL;
    req->req   = heq;
}

/**
 * Creates a new authorization request for the #SteamApi user. This is
 * typically called twice to complete the authorization process. First,
 * the user is authenticated partially, and then the Steam Guard code
 * is requested. Then, with the Steam Guard code, the authentication
 * process can be completed.
 *
 * @param api      The #SteamApi.
 * @param user     The username.
 * @param pass     The password.
 * @param authcode The authorization code (Steam Guard) or NULL.
 * @param captcha  The captcha code or NULL.
 * @param func     The #SteamApiFunc or NULL.
 * @param data     The user defined data or NULL.
 **/
void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;
    GTimeVal     tv;
    gchar       *pswd;
    gchar       *ms;

    g_return_if_fail(api       != NULL);
    g_return_if_fail(api->auth != NULL);

    pswd = steam_auth_key_encrypt(api->auth, pass);
    req  = steam_api_req_new(api, STEAM_API_REQ_TYPE_AUTH, func, data);

    if (pswd == NULL) {
        g_set_error(&req->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to encrypt password");

        steam_api_req_func(req);
        steam_api_req_free(req);
        return;
    }

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("username",        user),
        STEAM_HTTP_PAIR("password",        pswd),
        STEAM_HTTP_PAIR("emailauth",       authcode),
        STEAM_HTTP_PAIR("emailsteamid",    api->auth->esid),
        STEAM_HTTP_PAIR("captchagid",      api->auth->cgid),
        STEAM_HTTP_PAIR("captcha_text",    captcha),
        STEAM_HTTP_PAIR("rsatimestamp",    api->auth->time),
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
 * Implemented #GTraverseFunc for #steam_api_auth_rdir(). This adds
 * each key/value pair as parameters to the #SteamHttpReq.
 *
 * @param key The key.
 * @param val The value.
 * @param req The #SteamHttpReq.
 *
 * @return FALSE to continue the traversal.
 **/
static gboolean steam_api_params(gchar *key, gchar *val, SteamHttpReq *req)
{
    steam_http_req_params_set(req, STEAM_HTTP_PAIR(key, val), NULL);
    return FALSE;
}

/**
 * Creates a new authorization redirect request for the #SteamApi user.
 * This is called after the initial authorization process has been
 * finished with #steam_api_auth(). With the provided OAuth parameters,
 * this will provide session information which is later used by the
 * #SteamApi.
 *
 * @param req    The #SteamApiReq.
 * @param params The #GTree of OAuth parameters.
 **/
static void steam_api_auth_rdir(SteamApiReq *req, GTree *params)
{
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_AUTH_RDIR);
    g_tree_foreach(params, (GTraverseFunc) steam_api_params, req->req);

    req->type        = STEAM_API_REQ_TYPE_AUTH_RDIR;
    req->flags      |= STEAM_API_REQ_FLAG_NOCALL | STEAM_API_REQ_FLAG_NOFREE |
                       STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new chatlog request for a Steam friend. This will retrieve
 * read and unread messages from the Steam friend. If there are unread
 * messages, this will also mark them as read.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param func The #SteamApiListFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_chatlog(SteamApi *api, const SteamUserId *id,
                       SteamApiListFunc func, gpointer data)
{
    SteamApiReq *req;
    gchar       *path;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    path = g_strconcat(STEAM_COM_PATH_CHATLOG, id->commu.s, NULL);
    req  = steam_api_req_new(api, STEAM_API_REQ_TYPE_CHATLOG, func, data);

    steam_api_req_init(req, STEAM_COM_HOST, path);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionid", api->sessid),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(path);
}

/**
 * Creates a new friend accept request for a Steam user. If a someone
 * has requested friendship with the #SteamApi user, this will accept
 * the friendship request.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param func The #SteamApiIdFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_friend_accept(SteamApi *api, const SteamUserId *id,
                             const gchar *action, SteamApiIdFunc func,
                             gpointer data)
{
    SteamApiReq *req;
    gchar       *url;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    url = g_strdup_printf("%s%s/home_process", STEAM_COM_PATH_PROFILE,
                          api->id->steam.s);
    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIEND_ACCEPT, func, data);
    steam_api_req_init(req, STEAM_COM_HOST, url);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("id",        id->steam.s),
        STEAM_HTTP_PAIR("perform",   action),
        STEAM_HTTP_PAIR("action",    "approvePending"),
        STEAM_HTTP_PAIR("itype",     "friend"),
        STEAM_HTTP_PAIR("json",      "1"),
        STEAM_HTTP_PAIR("xml",       "0"),
        NULL
    );

    req->rdata = steam_user_id_dup(id);
    req->rfunc = (GDestroyNotify) steam_user_id_free;

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
    g_free(url);
}

/**
 * Creates a new friend add request for a Steam user. This will request
 * the friendship of another Steam user. The Steam user is not really
 * a friend until they accept the request on their end.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param func The #SteamApiIdFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_friend_add(SteamApi *api, const SteamUserId *id,
                          SteamApiIdFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIEND_ADD, func, data);
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_ADD);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("steamid",   id->steam.s),
        NULL
    );

    req->rdata = steam_user_id_dup(id);
    req->rfunc = (GDestroyNotify) steam_user_id_free;

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new friend ignore request for a Steam user. This either will
 * ignore or unignore a Steam user.
 *
 * @param api    The #SteamApi.
 * @param id     The #SteamUserId.
 * @param ignore TRUE to ignore, or FALSE to unignore.
 * @param func   The #SteamApiIdFunc or NULL.
 * @param data   The user defined data or NULL.
 **/
void steam_api_friend_ignore(SteamApi *api, const SteamUserId *id,
                             gboolean ignore,
                             SteamApiIdFunc func, gpointer data)
{
    SteamApiReq *req;
    const gchar *act;
    gchar       *user;
    gchar       *url;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    act  = ignore ? "ignore" : "unignore";
    user = g_strdup_printf("friends[%s]", id->steam.s);
    url  = g_strdup_printf("%s%s/friends/", STEAM_COM_PATH_PROFILE,
                           api->id->steam.s);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIEND_IGNORE, func, data);
    steam_api_req_init(req, STEAM_COM_HOST, url);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("action",    act),
        STEAM_HTTP_PAIR(user,        "1"),
        NULL
    );

    req->rdata = steam_user_id_dup(id);
    req->rfunc = (GDestroyNotify) steam_user_id_free;

    req->flags      |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(url);
    g_free(user);
}

/**
 * Creates a new friend remove request for a Steam user. This will
 * remove a Steam friend from the friend list of the #SteamApi user.
 * This does not block the user, see: #steam_api_friend_ignore().
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param func The #SteamApiIdFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_friend_remove(SteamApi *api, const SteamUserId *id,
                             SteamApiIdFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIEND_REMOVE, func, data);
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_REMOVE);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("steamid",   id->steam.s),
        NULL
    );

    req->rdata = steam_user_id_dup(id);
    req->rfunc = (GDestroyNotify) steam_user_id_free;

    req->flags      |= STEAM_API_REQ_FLAG_NOJSON;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new friend search request. This searches for Steam users
 * based on a search term. This is very useful when attempting to add
 * Steam users by their name via #steam_api_friend_add(). 
 *
 * @param api    The #SteamApi.
 * @param search The search term.
 * @param count  The amount of search results.
 * @param func   The #SteamApiListFunc or NULL.
 * @param data   The user defined data or NULL.
 **/
void steam_api_friend_search(SteamApi *api, const gchar *search, guint count,
                             SteamApiListFunc func, gpointer data)
{
    SteamApiReq *req;
    gchar       *scnt;
    gchar       *str;

    g_return_if_fail(api != NULL);

    str  = g_strdup_printf("\"%s\"", search);
    scnt = g_strdup_printf("%u", count);
    req  = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIEND_SEARCH, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIEND_SEARCH);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("keywords",     str),
        STEAM_HTTP_PAIR("count",        scnt),
        STEAM_HTTP_PAIR("offset",       "0"),
        STEAM_HTTP_PAIR("fields",       "all"),
        STEAM_HTTP_PAIR("targets",      "users"),
        NULL
    );

    steam_http_req_send(req->req);
    g_free(scnt);
    g_free(str);
}

/**
 * Creates a new friend list request for the #SteamApi user. This
 * returns the entire list of friends for the #SteamApi user,
 * including ignored friends.
 *
 * @param api    The #SteamApi.
 * @param func   The #SteamApiListFunc or NULL.
 * @param data   The user defined data or NULL.
 **/
void steam_api_friends(SteamApi *api, SteamApiListFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_FRIENDS, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_FRIENDS);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("steamid",      api->id->steam.s),
        STEAM_HTTP_PAIR("relationship", "friend,ignoredfriend"),
        NULL
    );

    steam_http_req_send(req->req);
}

/**
 * Creates a new friends chat info request for the #SteamApi user. This
 * gets additional information for the friends of the #SteamApi user.
 * Information such as last viewed times, which can be used with
 * #steam_api_chatlog() for displaying unread messages.
 *
 * @param req The #SteamApiReq.
 **/
static void steam_api_friends_cinfo(SteamApiReq *req)
{
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_CHAT);

    req->type   = STEAM_API_REQ_TYPE_FRIENDS_CINFO;
    req->flags |= STEAM_API_REQ_FLAG_NOCALL | STEAM_API_REQ_FLAG_NOFREE |
                  STEAM_API_REQ_FLAG_NOJSON;
    steam_http_req_send(req->req);
}

/**
 * Creates a new key request for the #SteamApi user. This is PKCS key
 * is used to encrypt the password before it is sent during the
 * authentication phase. 
 *
 * @param api  The #SteamApi.
 * @param user The username.
 * @param func The #SteamApiFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_key(SteamApi *api, const gchar *user,
                   SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;
    gchar       *ms;
    GTimeVal     tv;

    g_return_if_fail(api != NULL);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_KEY, func, data);
    steam_api_req_init(req, STEAM_COM_HOST, STEAM_COM_PATH_KEY);

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
 * Creates a new logoff request for the #SteamApi user. This simply
 * logs the #SteamApi user off.
 *
 * @param api  The #SteamApi.
 * @param func The #SteamApiFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_LOGOFF, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGOFF);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new logon request for the #SteamApi user. This simply logs
 * the #SteamApi user on. The #SteamApi user must be authenticated via
 * #steam_api_auth() before they can logon.
 *
 * @param api  The #SteamApi.
 * @param func The #SteamApiFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_LOGON, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("ui_mode",      "web"),
        NULL
    );

    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new logon request for the #SteamApi user. This simply
 * relogs the #SteamApi user after the session has gone stale.
 *
 * @param req The #SteamApiReq.
 **/
static void steam_api_relogon(SteamApiReq *req)
{
    steam_http_queue_pause(req->api->http, TRUE);
    steam_http_req_resend(req->req);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("umqid",        req->api->umqid),
        STEAM_HTTP_PAIR("ui_mode",      "web"),
        NULL
    );

    req->type        = STEAM_API_REQ_TYPE_RELOGON;
    req->flags      |= STEAM_API_REQ_FLAG_NOCALL | STEAM_API_REQ_FLAG_NOFREE;
    req->req->flags |= STEAM_HTTP_REQ_FLAG_POST | STEAM_HTTP_REQ_FLAG_NOWAIT;
    steam_http_req_send(req->req);
}

/**
 * Creates a new message request. This sends a #SteamUserMsg to
 * a Steam friend.
 *
 * @param api  The #SteamApi.
 * @param msg  The #SteamUserMsg.
 * @param func The #SteamApiFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_message(SteamApi *api, const SteamUserMsg *msg,
                       SteamApiFunc func, gpointer data)
{
    SteamApiReq *req;
    const gchar *type;

    g_return_if_fail(api != NULL);
    g_return_if_fail(msg != NULL);

    type = steam_user_msg_type_str(msg->type);
    req  = steam_api_req_new(api, STEAM_API_REQ_TYPE_MESSAGE, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_MESSAGE);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("steamid_dst",  msg->info->id->steam.s),
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

    req->req->flags |= STEAM_HTTP_REQ_FLAG_QUEUED | STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);
}

/**
 * Creates a new poll request for the #SteamApi user. This retrieves
 * messages from Steam friends. Additionally, this keeps the session
 * for the #SteamApi user active, and it must be called every 30
 * seconds. 
 *
 * @param api  The #SteamApi.
 * @param func The #SteamApiListFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_poll(SteamApi *api, SteamApiListFunc func, gpointer data)
{
    SteamApiReq *req;
    gchar       *lmid;
    gchar       *tout;

    g_return_if_fail(api != NULL);

    lmid = g_strdup_printf("%" G_GINT64_FORMAT, api->lmid);
    tout = g_strdup_printf("%" G_GINT32_FORMAT, STEAM_API_TIMEOUT);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_POLL, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_POLL);

    steam_http_req_headers_set(req->req,
        STEAM_HTTP_PAIR("Connection", "Keep-Alive"),
        NULL
    );

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("message",      lmid),
        STEAM_HTTP_PAIR("sectimeout",   tout),
        NULL
    );

    req->req->timeout  = (STEAM_API_TIMEOUT + 5) * 1000;
    req->req->flags   |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(req->req);

    g_free(tout);
    g_free(lmid);
}

/**
 * Creates a new summary request. This retrieves the summaries of
 * all users in the #SteamApiReq->infos list.
 *
 * @param req The #SteamApiReq.
 **/
static void steam_api_summaries(SteamApiReq *req)
{
    SteamUserInfo *info;
    GHashTable    *tbl;
    GString       *gstr;
    GList         *l;
    gsize          i;

    if (G_UNLIKELY(req->infos == NULL))
        return;

    tbl  = g_hash_table_new(g_int64_hash, g_int64_equal);
    gstr = g_string_sized_new(2048);

    for (l = req->infos, i = 0; l != NULL; l = l->next) {
        info = l->data;

        if (g_hash_table_contains(tbl, &info->id->steam.i))
            continue;

        g_hash_table_add(tbl, &info->id->steam.i);
        g_string_append_printf(gstr, "%s,", info->id->steam.s);

        if ((++i % 100) == 0)
            break;
    }

    /* Remove trailing comma */
    gstr->str[gstr->len - 1] = 0;
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", req->api->token),
        STEAM_HTTP_PAIR("steamids",     gstr->str),
        NULL
    );

    req->type   = STEAM_API_REQ_TYPE_SUMMARIES;
    req->flags |= STEAM_API_REQ_FLAG_NOCALL | STEAM_API_REQ_FLAG_NOFREE;
    steam_http_req_send(req->req);

    g_string_free(gstr, TRUE);
    g_hash_table_destroy(tbl);
}

/**
 * Creates a new summary request. This retrieves the summary of a Steam
 * friend.
 *
 * @param api  The #SteamApi.
 * @param id   The #SteamUserId.
 * @param func The #SteamApiInfoFunc or NULL.
 * @param data The user defined data or NULL.
 **/
void steam_api_summary(SteamApi *api, const SteamUserId *id,
                       SteamApiInfoFunc func, gpointer data)
{
    SteamApiReq *req;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    req = steam_api_req_new(api, STEAM_API_REQ_TYPE_SUMMARY, func, data);
    steam_api_req_init(req, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(req->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("steamids",     id->steam.s),
        NULL
    );

    steam_http_req_send(req->req);
}
