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

typedef void (*SteamApiParseFunc) (SteamApiData *sata, json_value *json);

static void steam_api_auth_rdir(SteamApiData *sata, GTree *params);
static void steam_api_friends_cinfo(SteamApiData *sata);
static void steam_api_relogon(SteamApiData *sata);
static void steam_api_summaries(SteamApiData *sata);

GQuark steam_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-api-error-quark");

    return q;
}

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

    api->id   = steam_friend_id_new(0);
    api->http = steam_http_new(STEAM_API_AGENT);

    return api;
}

void steam_api_free(SteamApi *api)
{
    if (G_UNLIKELY(api == NULL))
        return;

    steam_auth_free(api->auth);
    steam_http_free(api->http);
    steam_friend_id_free(api->id);

    g_free(api->sessid);
    g_free(api->token);
    g_free(api->umqid);
    g_free(api);
}

gchar *steam_api_profile_url(SteamFriendId *id)
{
    g_return_val_if_fail(id != NULL, NULL);

    return g_strdup_printf("https://%s%s%s/", STEAM_COM_HOST,
                           STEAM_COM_PATH_PROFILE, id->steam.s);
}

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

const gchar *steam_api_type_str(SteamApiType type)
{
    static const gchar *strs[STEAM_API_TYPE_LAST] = {
        [STEAM_API_TYPE_AUTH]          = "Authentication",
        [STEAM_API_TYPE_AUTH_RDIR]     = "Authentication (redirect)",
        [STEAM_API_TYPE_CHATLOG]       = "ChatLog",
        [STEAM_API_TYPE_FRIEND_ACCEPT] = "Friend Acceptance",
        [STEAM_API_TYPE_FRIEND_ADD]    = "Friend Addition",
        [STEAM_API_TYPE_FRIEND_IGNORE] = "Friend Ignore",
        [STEAM_API_TYPE_FRIEND_REMOVE] = "Friend Removal",
        [STEAM_API_TYPE_FRIEND_SEARCH] = "Friend Search",
        [STEAM_API_TYPE_FRIENDS]       = "Friends",
        [STEAM_API_TYPE_FRIENDS_CINFO] = "Friends Chat Info",
        [STEAM_API_TYPE_KEY]           = "Key",
        [STEAM_API_TYPE_LOGON]         = "Logon",
        [STEAM_API_TYPE_RELOGON]       = "Relogon",
        [STEAM_API_TYPE_LOGOFF]        = "Logoff",
        [STEAM_API_TYPE_MESSAGE]       = "Message",
        [STEAM_API_TYPE_POLL]          = "Polling",
        [STEAM_API_TYPE_SUMMARIES]     = "Summaries",
        [STEAM_API_TYPE_SUMMARY]       = "Summary"
    };

    if ((type <= STEAM_API_TYPE_NONE) || (type >= STEAM_API_TYPE_LAST))
        return "Generic";

    return strs[type];
}

SteamApiData *steam_api_data_new(SteamApi *api, SteamApiType type,
                                 gpointer func, gpointer data)
{
    SteamApiData *sata;

    sata = g_new0(SteamApiData, 1);

    sata->type = type;
    sata->api  = api;
    sata->func = func;
    sata->data = data;

    return sata;
}

void steam_api_data_free(SteamApiData *sata)
{
    if (G_UNLIKELY(sata == NULL))
        return;

    if ((sata->rfunc != NULL) && (sata->rdata != NULL))
        sata->rfunc(sata->rdata);

    if (sata->sums != NULL)
        g_list_free(sata->sums);

    if (sata->err != NULL)
        g_error_free(sata->err);

    g_free(sata);
}

void steam_api_data_func(SteamApiData *sata)
{
    g_return_if_fail(sata != NULL);

    if (sata->func == NULL)
        return;

    switch (sata->type) {
    case STEAM_API_TYPE_AUTH:
    case STEAM_API_TYPE_KEY:
    case STEAM_API_TYPE_LOGOFF:
    case STEAM_API_TYPE_LOGON:
    case STEAM_API_TYPE_RELOGON:
    case STEAM_API_TYPE_MESSAGE:
        ((SteamApiFunc) sata->func)(sata->api, sata->err, sata->data);
        return;

    case STEAM_API_TYPE_FRIEND_ACCEPT:
    case STEAM_API_TYPE_FRIEND_ADD:
    case STEAM_API_TYPE_FRIEND_IGNORE:
    case STEAM_API_TYPE_FRIEND_REMOVE:
        ((SteamApiIdFunc) sata->func)(sata->api, sata->rdata, sata->err,
                                      sata->data);
        return;

    case STEAM_API_TYPE_CHATLOG:
    case STEAM_API_TYPE_FRIEND_SEARCH:
    case STEAM_API_TYPE_FRIENDS:
    case STEAM_API_TYPE_POLL:
        ((SteamApiListFunc) sata->func)(sata->api, sata->rdata, sata->err,
                                        sata->data);
        return;

    case STEAM_API_TYPE_SUMMARY:
        ((SteamApiSummaryFunc) sata->func)(sata->api, sata->rdata, sata->err,
                                           sata->data);
        return;

    default:
        return;
    }
}

SteamApiMessage *steam_api_message_new(gint64 id)
{
    SteamApiMessage *mesg;

    mesg = g_new0(SteamApiMessage, 1);
    mesg->smry = steam_friend_summary_new(id);

    return mesg;
}

SteamApiMessage *steam_api_message_new_str(const gchar *id)
{
    gint64 in;

    g_return_val_if_fail(id != NULL, NULL);

    in = g_ascii_strtoll(id, NULL, 10);
    return steam_api_message_new(in);
}

void steam_api_message_free(SteamApiMessage *mesg)
{
    if (G_UNLIKELY(mesg == NULL))
        return;

    steam_friend_summary_free(mesg->smry);

    g_free(mesg->text);
    g_free(mesg);
}

const gchar *steam_api_message_type_str(SteamApiMessageType type)
{
    static const gchar *strs[STEAM_API_MESSAGE_TYPE_LAST] = {
        [STEAM_API_MESSAGE_TYPE_SAYTEXT]      = "saytext",
        [STEAM_API_MESSAGE_TYPE_EMOTE]        = "emote",
        [STEAM_API_MESSAGE_TYPE_LEFT_CONV]    = "leftconversation",
        [STEAM_API_MESSAGE_TYPE_RELATIONSHIP] = "personarelationship",
        [STEAM_API_MESSAGE_TYPE_STATE]        = "personastate",
        [STEAM_API_MESSAGE_TYPE_TYPING]       = "typing"
    };

    if ((type < 0) || (type >= STEAM_API_MESSAGE_TYPE_LAST))
        return "";

    return strs[type];
}

SteamApiMessageType steam_api_message_type_from_str(const gchar *type)
{
    const gchar *s;
    guint        i;

    if (type == NULL)
        return STEAM_API_MESSAGE_TYPE_LAST;

    for (i = 0; i < STEAM_API_MESSAGE_TYPE_LAST; i++) {
        s = steam_api_message_type_str(i);

        if (g_ascii_strcasecmp(type, s) == 0)
            return i;
    }

    return STEAM_API_MESSAGE_TYPE_LAST;
}

static void steam_friend_summary_json(SteamFriendSummary *smry,
                                      json_value *json)
{
    const gchar *str;
    gint64       in;

    steam_json_str(json, "gameextrainfo", &str);
    smry->game = g_strdup(str);

    steam_json_str(json, "gameserverip", &str);
    smry->server = g_strdup(str);

    steam_json_str(json, "personaname", &str);
    smry->nick = g_strdup(str);

    steam_json_str(json, "realname", &str);
    smry->fullname = g_strdup(str);

    steam_json_int(json, "personastate", &in);
    smry->state = in;
}

static void steam_api_auth_cb(SteamApiData *sata, json_value *json)
{
    SteamApiError  err;
    json_value    *jv;
    const gchar   *str;
    GTree         *prms;

    if (steam_json_str(json, "captcha_gid", &str))
        steam_auth_captcha(sata->api->auth, str);

    if (steam_json_str(json, "emailsteamid", &str))
        steam_auth_email(sata->api->auth, str);

    if (!steam_json_bool(json, "success")) {
        if (steam_json_bool(json, "emailauth_needed"))
            err = STEAM_API_ERROR_AUTH_GUARD;
        else if (steam_json_bool(json, "captcha_needed"))
            err = STEAM_API_ERROR_AUTH_CAPTCHA;
        else
            err = STEAM_API_ERROR_AUTH;

        if (!steam_json_str(json, "message", &str))
            str = "Failed to authenticate";

        g_set_error(&sata->err, STEAM_API_ERROR, err, "%s", str);
        return;
    }

    if (!steam_json_val(json, "oauth", json_string, &jv)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth data");
        return;
    }

    json = steam_json_new(jv->u.string.ptr, jv->u.string.length, &sata->err);

    if ((json == NULL) || (sata->err != NULL))
        return;

    if (!steam_json_str(json, "oauth_token", &str)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth token");
        goto finish;
    }

    g_free(sata->api->token);
    sata->api->token = g_strdup(str);

    prms = steam_json_tree(json);
    steam_api_auth_rdir(sata, prms);
    g_tree_destroy(prms);

finish:
    json_value_free(json);
}

static void steam_api_auth_rdir_cb(SteamApiData *sata, json_value *json)
{
    const gchar *str;

    steam_http_cookies_parse_req(sata->api->http, sata->req);
    str = g_tree_lookup(sata->api->http->cookies, "sessionid");

    if (str == NULL) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to obtain OAuth session ID");
        return;
    }

    g_free(sata->api->sessid);
    sata->api->sessid = g_strdup(str);
}

static void steam_api_chatlog_free(GSList *messages)
{
    g_slist_free_full(messages, (GDestroyNotify) steam_api_message_free);
}

static void steam_api_chatlog_cb(SteamApiData *sata, json_value *json)
{
    SteamApiMessage *mesg;
    json_value      *jv;
    GSList          *messages;
    const gchar     *str;
    gint64           in;
    gsize            i;

    messages = NULL;

    for (i = 0; i < json->u.array.length; i++) {
        jv = json->u.array.values[i];
        steam_json_int(jv, "m_unAccountID", &in);

        if (in == sata->api->id->commu.i)
            continue;

        in = STEAM_FRIEND_ID_NEW(STEAM_FRIEND_ID_UNIVERSE_PUBLIC,
                                 STEAM_FRIEND_ID_TYPE_INDIVIDUAL,
                                 1, in);

        mesg = steam_api_message_new(in);
        mesg->type = STEAM_API_MESSAGE_TYPE_SAYTEXT;

        steam_json_str(jv, "m_strMessage",  &str);
        mesg->text = g_strdup(str);

        steam_json_int(jv, "m_tsTimestamp", &in);
        mesg->tstamp = in;

        messages = g_slist_prepend(messages, mesg);
    }

    sata->rdata = g_slist_reverse(messages);
    sata->rfunc = (GDestroyNotify) steam_api_chatlog_free;
}


static void steam_api_friend_accept_cb(SteamApiData *sata, json_value *json)
{
    const gchar *str;

    if (!steam_json_scmp(json, "error_text", "", &str))
        return;

    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_ACCEPT,
                "%s", str);
}

static void steam_api_friend_add_cb(SteamApiData *sata, json_value *json)
{
    json_value *jv;

    if (!steam_json_val(json, "failed_invites_result", json_array, &jv))
        return;

    if (jv->u.array.length < 1)
        return;

    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_ADD,
                "Failed to add friend");
}

static void steam_api_friend_ignore_cb(SteamApiData *sata, json_value *json)
{

}

static void steam_api_friend_remove_cb(SteamApiData *sata, json_value *json)
{
    if ((sata->req->body_size > 0) && bool2int(sata->req->body))
        return;

    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIEND_REMOVE,
                "Failed to remove friend");
}

static void steam_api_friend_search_free(GSList *results)
{
    g_slist_free_full(results, (GDestroyNotify) steam_friend_summary_free);
}

static void steam_api_friend_search_cb(SteamApiData *sata, json_value *json)
{
    SteamFriendSummary *smry;
    json_value         *jv;
    json_value         *je;
    GSList             *results;
    const gchar        *str;
    guint              i;

    if (!steam_json_val(json, "results", json_array, &jv))
        return;

    results = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_scmp(je, "type", "user", &str))
            continue;

        if (!steam_json_str(je, "steamid", &str))
            continue;

        smry = steam_friend_summary_new_str(str);

        steam_json_str(je, "matchingtext", &str);
        smry->nick = g_strdup(str);

        results = g_slist_prepend(results, smry);
    }

    sata->rdata = g_slist_reverse(results);
    sata->rfunc = (GDestroyNotify) steam_api_friend_search_free;
}

static void steam_api_friends_free(GSList *friends)
{
    g_slist_free_full(friends, (GDestroyNotify) steam_friend_summary_free);
}

static void steam_api_friends_cb(SteamApiData *sata, json_value *json)
{
    SteamFriendSummary *smry;
    SteamFriendAction   rlat;
    json_value         *jv;
    json_value         *je;
    GSList             *friends;
    const gchar        *str;
    guint               i;

    if (!steam_json_val(json, "friends", json_array, &jv))
        return;

    friends = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        steam_json_str(je, "relationship", &str);

        if (str == NULL)
            continue;

        if (g_ascii_strcasecmp(str, "friend") == 0)
            rlat = STEAM_FRIEND_RELATION_FRIEND;
        else if (g_ascii_strcasecmp(str, "ignoredfriend") == 0)
            rlat = STEAM_FRIEND_RELATION_IGNORE;
        else
            continue;

        if (!steam_json_str(je, "steamid", &str))
            continue;

        smry = steam_friend_summary_new_str(str);
        smry->relation = rlat;

        friends    = g_slist_prepend(friends, smry);
        sata->sums = g_list_prepend(sata->sums, smry);
    }

    sata->rdata = friends;
    sata->rfunc = (GDestroyNotify) steam_api_friends_free;

    if (friends != NULL)
        steam_api_friends_cinfo(sata);
}

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

static void steam_api_friends_cinfo_cb(SteamApiData *sata, json_value *json)
{
    SteamFriendSummary *smry;
    GHashTable         *stbl;
    json_value         *je;
    const gchar        *str;
    const gchar        *end;
    gchar              *jraw;
    gsize               size;
    GSList             *l;
    guint               i;

    str = strstr(sata->req->body, "CWebChat");
    str = unquotechr(str, '}');

    str = unquotechr(str, '[');
    end = unquotechr(str, ']');

    if ((str == NULL) || (end == NULL)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_FRIENDS_CINFO,
                    "Failed to obtain friends chat information");
        return;
    }

    size = (end - str) + 1;
    jraw = g_strndup(str, size);
    json = steam_json_new(jraw, size, &sata->err);

    if ((json == NULL) || (sata->err != NULL)) {
        g_free(jraw);
        return;
    }

    stbl = g_hash_table_new(g_str_hash, g_str_equal);

    for (l = sata->rdata; l != NULL; l = l->next) {
        smry = l->data;
        g_hash_table_insert(stbl, smry->id->steam.s, smry);
    }

    for (i = 0; i < json->u.array.length; i++) {
        je = json->u.array.values[i];

        if (!steam_json_str(je, "m_ulSteamID", &str))
            continue;

        smry = g_hash_table_lookup(stbl, str);

        if (smry == NULL)
            continue;

        steam_json_int(je, "m_tsLastMessage", &smry->lmesg);
        steam_json_int(je, "m_tsLastView",    &smry->lview);
    }

    g_hash_table_destroy(stbl);
    json_value_free(json);
    g_free(jraw);
}

static void steam_api_key_cb(SteamApiData *sata, json_value *json)
{
    SteamAuth   *auth;
    const gchar *str;

    if (steam_json_scmp(json, "success", "false", &str))
        goto error;

    auth = (sata->api->auth != NULL) ? sata->api->auth : steam_auth_new();

    if (!steam_json_str(json, "publickey_mod", &str) ||
        !steam_auth_key_mod(auth, str))
        goto error;

    if (!steam_json_str(json, "publickey_exp", &str) ||
        !steam_auth_key_exp(auth, str))
        goto error;

    if (steam_json_str(json, "timestamp", &str))
        auth->time = g_strdup(str);

    sata->api->auth = auth;
    return;

error:
    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_KEY,
                "Failed to retrieve authentication key");
}

static void steam_api_logon_cb(SteamApiData *sata, json_value *json)
{
    const gchar *str;
    gint64       in;

    if (!steam_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGON,
                    "%s", str);
        return;
    }

    steam_json_int(json, "message", &in);
    sata->api->lmid = in;

    steam_json_int(json, "utc_timestamp", &in);
    sata->api->tstamp = in;

    if (!steam_json_scmp(json, "steamid", sata->api->id->steam.s, &str)) {
        steam_friend_id_free(sata->api->id);
        sata->api->id = steam_friend_id_new_str(str);
    }

    if (!steam_json_scmp(json, "umqid", sata->api->umqid, &str)) {
        g_free(sata->api->umqid);
        sata->api->umqid = g_strdup(str);
    }
}

static void steam_api_relogon_cb(SteamApiData *sata, json_value *json)
{
    const gchar  *str;

    steam_http_queue_pause(sata->api->http, FALSE);

    if (!steam_json_scmp(json, "error", "OK", &str)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_RELOGON,
                    "%s", str);
        return;
    }

    sata->flags |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE;
}

static void steam_api_logoff_cb(SteamApiData *sata, json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

static void steam_api_message_cb(SteamApiData *sata, json_value *json)
{
    const gchar *str;

    if (steam_json_scmp(json, "error", "OK", &str))
        return;

    if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
        steam_api_relogon(sata);
        return;
    }

    g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_LOGOFF,
                "%s", str);
}

static void steam_api_poll_free(GSList *messages)
{
    g_slist_free_full(messages, (GDestroyNotify) steam_api_message_free);
}

static void steam_api_poll_cb(SteamApiData *sata, json_value *json)
{
    SteamApiMessage   *mesg;
    SteamFriendIdType  type;
    json_value        *jv;
    json_value        *je;
    GSList            *messages;
    const gchar       *str;
    gint64             in;
    guint              i;

    if (!steam_json_scmp(json, "error", "OK", &str))
    {
        if (g_ascii_strcasecmp(str, "Not Logged On") == 0) {
            steam_api_relogon(sata);
            return;
        }

        if (g_ascii_strcasecmp(str, "Timeout") != 0) {
            g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        "%s", str);
            return;
        }

        steam_json_int(json, "sectimeout", &in);

        if (in < STEAM_API_TIMEOUT) {
            g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_POLL,
                        "Timeout of %" G_GINT64_FORMAT " too low", in);
            return;
        }
    }

    if (!steam_json_val(json, "messages", json_array, &jv) ||
        !steam_json_int(json, "messagelast", &in) ||
        (in == sata->api->lmid))
    {
        return;
    }

    sata->api->lmid = in;
    messages        = NULL;

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (steam_json_scmp(je, "steamid_from", sata->api->id->steam.s, &str))
            continue;

        in   = g_ascii_strtoll(str, NULL, 10);
        type = STEAM_FRIEND_ID_TYPE(in);

        /* For now, only handle individuals */
        if (type != STEAM_FRIEND_ID_TYPE_INDIVIDUAL)
            continue;

        mesg = steam_api_message_new_str(str);

        steam_json_str(je, "type", &str);
        steam_json_int(je, "utc_timestamp", &in);

        mesg->type   = steam_api_message_type_from_str(str);
        mesg->tstamp = in;

        switch (mesg->type) {
        case STEAM_API_MESSAGE_TYPE_SAYTEXT:
        case STEAM_API_MESSAGE_TYPE_EMOTE:
            steam_json_str(je, "text", &str);
            mesg->text = g_strdup(str);
            break;

        case STEAM_API_MESSAGE_TYPE_STATE:
            steam_json_str(je, "persona_name", &str);
            mesg->smry->nick = g_strdup(str);
            sata->sums       = g_list_prepend(sata->sums, mesg->smry);
            break;

        case STEAM_API_MESSAGE_TYPE_RELATIONSHIP:
            steam_json_int(je, "persona_state", &in);
            mesg->smry->action = in;
            sata->sums = g_list_prepend(sata->sums, mesg->smry);
            break;

        case STEAM_API_MESSAGE_TYPE_TYPING:
        case STEAM_API_MESSAGE_TYPE_LEFT_CONV:
            break;

        default:
            steam_api_message_free(mesg);
            continue;
        }

        messages = g_slist_prepend(messages, mesg);
    }

    sata->rdata = g_slist_reverse(messages);
    sata->rfunc = (GDestroyNotify) steam_api_poll_free;
}

static void steam_api_summaries_cb(SteamApiData *sata, json_value *json)
{
    SteamFriendSummary *smry;
    json_value         *jv;
    json_value         *je;
    const gchar        *str;
    GList              *l;
    GList              *c;
    guint               i;

    if ((!steam_json_val(json, "players", json_array, &jv) ||
         (jv->u.array.length < 1)) &&
        (sata->sums != NULL))
    {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARIES,
                    "Failed to retrieve requested friend summaries");
        return;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        je = jv->u.array.values[i];

        if (!steam_json_str(je, "steamid", &str))
            continue;

        for (l = sata->sums; l != NULL; ) {
            smry = l->data;

            if (g_strcmp0(smry->id->steam.s, str) != 0) {
                l = l->next;
                continue;
            }

            c = l;
            l = l->next;

            sata->sums = g_list_delete_link(sata->sums, c);
            steam_friend_summary_json(smry, je);
        }
    }
}

static void steam_api_summary_cb(SteamApiData *sata, json_value *json)
{
    SteamFriendSummary *smry;
    json_value         *jv;
    const gchar        *str;

    if (!steam_json_val(json, "players", json_array, &jv) ||
        (jv->u.array.length != 1))
    {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARY,
                    "Failed to retrieve friend summary");
        return;
    }

    jv = jv->u.array.values[0];

    if (!steam_json_str(jv, "steamid", &str)) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_SUMMARY,
                    "Failed to retrieve friend summary steamid");
        return;
    }

    smry = steam_friend_summary_new_str(str);
    steam_friend_summary_json(smry, jv);

    sata->rdata = smry;
    sata->rfunc = (GDestroyNotify) steam_friend_summary_free;
}

static void steam_api_cb(SteamHttpReq *req, gpointer data)
{
    SteamApiData *sata = data;
    SteamApiData *tata;
    SteamApiType  type;
    json_value   *json;

    static const SteamApiParseFunc pfuncs[STEAM_API_TYPE_LAST] = {
        [STEAM_API_TYPE_AUTH]          = steam_api_auth_cb,
        [STEAM_API_TYPE_AUTH_RDIR]     = steam_api_auth_rdir_cb,
        [STEAM_API_TYPE_CHATLOG]       = steam_api_chatlog_cb,
        [STEAM_API_TYPE_FRIEND_ACCEPT] = steam_api_friend_accept_cb,
        [STEAM_API_TYPE_FRIEND_ADD]    = steam_api_friend_add_cb,
        [STEAM_API_TYPE_FRIEND_IGNORE] = steam_api_friend_ignore_cb,
        [STEAM_API_TYPE_FRIEND_REMOVE] = steam_api_friend_remove_cb,
        [STEAM_API_TYPE_FRIEND_SEARCH] = steam_api_friend_search_cb,
        [STEAM_API_TYPE_FRIENDS]       = steam_api_friends_cb,
        [STEAM_API_TYPE_FRIENDS_CINFO] = steam_api_friends_cinfo_cb,
        [STEAM_API_TYPE_KEY]           = steam_api_key_cb,
        [STEAM_API_TYPE_LOGOFF]        = steam_api_logoff_cb,
        [STEAM_API_TYPE_LOGON]         = steam_api_logon_cb,
        [STEAM_API_TYPE_RELOGON]       = steam_api_relogon_cb,
        [STEAM_API_TYPE_MESSAGE]       = steam_api_message_cb,
        [STEAM_API_TYPE_POLL]          = steam_api_poll_cb,
        [STEAM_API_TYPE_SUMMARIES]     = steam_api_summaries_cb,
        [STEAM_API_TYPE_SUMMARY]       = steam_api_summary_cb
    };

    /* Ensure the active request is defined */
    sata->req = req;

    if (sata->typel != STEAM_API_TYPE_NONE) {
        type = sata->typel;
        sata->typel = STEAM_API_TYPE_NONE;
    } else {
        type = sata->type;
    }

    if ((type <= STEAM_API_TYPE_NONE) || (type >= STEAM_API_TYPE_LAST)) {
        req->flags &= ~STEAM_HTTP_REQ_FLAG_NOFREE;
        steam_api_data_free(sata);
        g_return_if_reached();
    }

    tata = g_memdup(sata, sizeof (SteamApiData));
    sata->flags = 0;

    if (req->err != NULL) {
        g_propagate_error(&sata->err, req->err);
        req->err = NULL;
    }

    if (sata->err == NULL)
    {
        if (!(tata->flags & STEAM_API_FLAG_NOJSON)) {
            json = steam_json_new(req->body, req->body_size, &sata->err);

            if (sata->err == NULL)
                pfuncs[type](sata, json);

            if (json != NULL)
                json_value_free(json);
        } else {
            pfuncs[type](sata, NULL);
        }
    }

    if ((sata->err == NULL) &&
        (sata->sums != NULL) &&
        (sata->type == tata->type))
    {
        steam_api_summaries(sata);
    }

    if (sata->type != tata->type) {
        sata->typel = sata->type;
        sata->type  = tata->type;
    }

    if (!(sata->flags & STEAM_API_FLAG_NOCALL)) {
        if (sata->err != NULL)
            g_prefix_error(&sata->err, "%s: ", steam_api_type_str(type));

        steam_api_data_func(sata);
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_NOFREE)
        sata->flags |= STEAM_API_FLAG_NOFREE;

    if (!(sata->flags & STEAM_API_FLAG_NOFREE)) {
        sata->req = NULL;
        steam_api_data_free(sata);
    } else if (sata->err != NULL) {
        g_error_free(sata->err);
        sata->err = NULL;
    }

    g_free(tata);
}

static void steam_api_data_req(SteamApiData *sata, const gchar *host,
                               const gchar *path)
{
    SteamApi     *api = sata->api;
    SteamHttpReq *req;

    req = steam_http_req_new(api->http, host, 443, path, steam_api_cb, sata);

    req->flags = STEAM_HTTP_REQ_FLAG_SSL;
    sata->req  = req;
}

void steam_api_auth(SteamApi *api, const gchar *user, const gchar *pass,
                    const gchar *authcode, const gchar *captcha,
                    SteamApiFunc func, gpointer data)
{
    SteamApiData *sata;
    GTimeVal      tv;
    gchar        *pswd;
    gchar        *ms;

    g_return_if_fail(api       != NULL);
    g_return_if_fail(api->auth != NULL);

    pswd = steam_auth_key_encrypt(api->auth, pass);
    sata = steam_api_data_new(api, STEAM_API_TYPE_AUTH, func, data);

    if (pswd == NULL) {
        g_set_error(&sata->err, STEAM_API_ERROR, STEAM_API_ERROR_AUTH,
                    "Failed to encrypt password");

        steam_api_data_func(sata);
        steam_api_data_free(sata);
        return;
    }

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_AUTH);

    steam_http_req_params_set(sata->req,
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

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);

    g_free(pswd);
    g_free(ms);
}

static gboolean steam_api_params(gchar *key, gchar *val, SteamHttpReq *req)
{
    steam_http_req_params_set(req, STEAM_HTTP_PAIR(key, val), NULL);
    return FALSE;
}

static void steam_api_auth_rdir(SteamApiData *sata, GTree *params)
{
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_AUTH_RDIR);
    g_tree_foreach(params, (GTraverseFunc) steam_api_params, sata->req);

    sata->type        = STEAM_API_TYPE_AUTH_RDIR;
    sata->flags      |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE |
                        STEAM_API_FLAG_NOJSON;
    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

void steam_api_chatlog(SteamApi *api, SteamFriendId *id,
                       SteamApiListFunc func, gpointer data)
{
    SteamApiData *sata;
    gchar        *path;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    path = g_strconcat(STEAM_COM_PATH_CHATLOG, id->commu.s, NULL);
    sata = steam_api_data_new(api, STEAM_API_TYPE_CHATLOG, func, data);

    steam_api_data_req(sata, STEAM_COM_HOST, path);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("sessionid", api->sessid),
        NULL
    );

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);

    g_free(path);
}

void steam_api_friend_accept(SteamApi *api, SteamFriendId *id,
                             const gchar *action, SteamApiIdFunc func,
                             gpointer data)
{
    SteamApiData *sata;
    gchar        *url;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    url  = g_strdup_printf("%s%s/home_process", STEAM_COM_PATH_PROFILE,
                           api->id->steam.s);
    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIEND_ACCEPT, func, data);
    steam_api_data_req(sata, STEAM_COM_HOST, url);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("id",        id->steam.s),
        STEAM_HTTP_PAIR("perform",   action),
        STEAM_HTTP_PAIR("action",    "approvePending"),
        STEAM_HTTP_PAIR("itype",     "friend"),
        STEAM_HTTP_PAIR("json",      "1"),
        STEAM_HTTP_PAIR("xml",       "0"),
        NULL
    );

    sata->rdata = steam_friend_id_dup(id);
    sata->rfunc = (GDestroyNotify) steam_friend_id_free;

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
    g_free(url);
}

void steam_api_friend_add(SteamApi *api, SteamFriendId *id,
                          SteamApiIdFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIEND_ADD, func, data);
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_ADD);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("steamid",   id->steam.s),
        NULL
    );

    sata->rdata = steam_friend_id_dup(id);
    sata->rfunc = (GDestroyNotify) steam_friend_id_free;

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

void steam_api_friend_ignore(SteamApi *api, SteamFriendId *id, gboolean ignore,
                             SteamApiIdFunc func, gpointer data)
{
    SteamApiData *sata;
    const gchar  *act;
    gchar        *frnd;
    gchar        *url;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    act  = ignore ? "ignore" : "unignore";
    frnd = g_strdup_printf("friends[%s]", id->steam.s);
    url  = g_strdup_printf("%s%s/friends/", STEAM_COM_PATH_PROFILE,
                           api->id->steam.s);

    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIEND_IGNORE, func, data);
    steam_api_data_req(sata, STEAM_COM_HOST, url);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("action",    act),
        STEAM_HTTP_PAIR(frnd,        "1"),
        NULL
    );

    sata->rdata = steam_friend_id_dup(id);
    sata->rfunc = (GDestroyNotify) steam_friend_id_free;

    sata->flags      |= STEAM_API_FLAG_NOJSON;
    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);

    g_free(url);
    g_free(frnd);
}

void steam_api_friend_remove(SteamApi *api, SteamFriendId *id,
                             SteamApiIdFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIEND_REMOVE, func, data);
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_FRIEND_REMOVE);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("sessionID", api->sessid),
        STEAM_HTTP_PAIR("steamid",   id->steam.s),
        NULL
    );

    sata->rdata = steam_friend_id_dup(id);
    sata->rfunc = (GDestroyNotify) steam_friend_id_free;

    sata->flags      |= STEAM_API_FLAG_NOJSON;
    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

void steam_api_friend_search(SteamApi *api, const gchar *search, guint count,
                             SteamApiListFunc func, gpointer data)
{
    SteamApiData *sata;
    gchar        *scnt;
    gchar        *str;

    g_return_if_fail(api != NULL);

    str  = g_strdup_printf("\"%s\"", search);
    scnt = g_strdup_printf("%u", count);
    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIEND_SEARCH, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_FRIEND_SEARCH);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("keywords",     str),
        STEAM_HTTP_PAIR("count",        scnt),
        STEAM_HTTP_PAIR("offset",       "0"),
        STEAM_HTTP_PAIR("fields",       "all"),
        STEAM_HTTP_PAIR("targets",      "users"),
        NULL
    );

    steam_http_req_send(sata->req);
    g_free(scnt);
    g_free(str);
}

void steam_api_friends(SteamApi *api, SteamApiListFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_FRIENDS, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_FRIENDS);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("steamid",      api->id->steam.s),
        STEAM_HTTP_PAIR("relationship", "friend,ignoredfriend"),
        NULL
    );

    steam_http_req_send(sata->req);
}

static void steam_api_friends_cinfo(SteamApiData *sata)
{
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_CHAT);

    sata->type   = STEAM_API_TYPE_FRIENDS_CINFO;
    sata->flags |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE |
                   STEAM_API_FLAG_NOJSON;
    steam_http_req_send(sata->req);
}

void steam_api_key(SteamApi *api, const gchar *user,
                   SteamApiFunc func, gpointer data)
{
    SteamApiData *sata;
    gchar        *ms;
    GTimeVal      tv;

    g_return_if_fail(api != NULL);

    g_get_current_time(&tv);
    ms = g_strdup_printf("%ld", (tv.tv_usec / 1000));

    sata = steam_api_data_new(api, STEAM_API_TYPE_KEY, func, data);
    steam_api_data_req(sata, STEAM_COM_HOST, STEAM_COM_PATH_KEY);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("username",   user),
        STEAM_HTTP_PAIR("donotcache", ms),
        NULL
    );

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
    g_free(ms);
}

void steam_api_logoff(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_LOGOFF, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_LOGOFF);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        NULL
    );

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

void steam_api_logon(SteamApi *api, SteamApiFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_LOGON, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("ui_mode",      "web"),
        NULL
    );

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

static void steam_api_relogon(SteamApiData *sata)
{
    steam_http_queue_pause(sata->api->http, TRUE);
    steam_http_req_resend(sata->req);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_LOGON);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", sata->api->token),
        STEAM_HTTP_PAIR("umqid",        sata->api->umqid),
        STEAM_HTTP_PAIR("ui_mode",      "web"),
        NULL
    );

    sata->type        = STEAM_API_TYPE_RELOGON;
    sata->flags      |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE;
    sata->req->flags |= STEAM_HTTP_REQ_FLAG_POST | STEAM_HTTP_REQ_FLAG_NOWAIT;
    steam_http_req_send(sata->req);
}

void steam_api_message(SteamApi *api, const SteamApiMessage *mesg,
                       SteamApiFunc func, gpointer data)
{
    SteamApiData *sata;
    const gchar  *type;

    g_return_if_fail(api  != NULL);
    g_return_if_fail(mesg != NULL);

    type = steam_api_message_type_str(mesg->type);
    sata = steam_api_data_new(api, STEAM_API_TYPE_MESSAGE, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_MESSAGE);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("steamid_dst",  mesg->smry->id->steam.s),
        STEAM_HTTP_PAIR("type",         type),
        NULL
    );

    switch (mesg->type) {
    case STEAM_API_MESSAGE_TYPE_SAYTEXT:
    case STEAM_API_MESSAGE_TYPE_EMOTE:
        steam_http_req_params_set(sata->req,
            STEAM_HTTP_PAIR("text", mesg->text),
            NULL
        );
        break;

    case STEAM_API_MESSAGE_TYPE_TYPING:
        break;

    default:
        steam_http_req_free(sata->req);
        return;
    }

    sata->req->flags |= STEAM_HTTP_REQ_FLAG_QUEUED | STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);
}

void steam_api_poll(SteamApi *api, SteamApiListFunc func, gpointer data)
{
    SteamApiData *sata;
    gchar        *lmid;
    gchar        *tout;

    g_return_if_fail(api != NULL);

    lmid = g_strdup_printf("%" G_GINT64_FORMAT, api->lmid);
    tout = g_strdup_printf("%" G_GINT32_FORMAT, STEAM_API_TIMEOUT);

    sata = steam_api_data_new(api, STEAM_API_TYPE_POLL, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_POLL);

    steam_http_req_headers_set(sata->req,
        STEAM_HTTP_PAIR("Connection", "Keep-Alive"),
        NULL
    );

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("umqid",        api->umqid),
        STEAM_HTTP_PAIR("message",      lmid),
        STEAM_HTTP_PAIR("sectimeout",   tout),
        NULL
    );

    sata->req->timeout  = (STEAM_API_TIMEOUT + 5) * 1000;
    sata->req->flags   |= STEAM_HTTP_REQ_FLAG_POST;
    steam_http_req_send(sata->req);

    g_free(tout);
    g_free(lmid);
}

static void steam_api_summaries(SteamApiData *sata)
{
    SteamFriendSummary *smry;
    GHashTable         *tbl;
    GString            *gstr;
    GList              *l;
    gsize               i;

    if (G_UNLIKELY(sata->sums == NULL))
        return;

    tbl  = g_hash_table_new(g_int64_hash, g_int64_equal);
    gstr = g_string_sized_new(2048);

    for (l = sata->sums, i = 0; l != NULL; l = l->next) {
        smry = l->data;

        if (g_hash_table_contains(tbl, &smry->id->steam.i))
            continue;

        g_hash_table_add(tbl, &smry->id->steam.i);
        g_string_append_printf(gstr, "%s,", smry->id->steam.s);

        if ((++i % 100) == 0)
            break;
    }

    /* Remove trailing comma */
    gstr->str[gstr->len - 1] = 0;
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", sata->api->token),
        STEAM_HTTP_PAIR("steamids",     gstr->str),
        NULL
    );

    sata->type   = STEAM_API_TYPE_SUMMARIES;
    sata->flags |= STEAM_API_FLAG_NOCALL | STEAM_API_FLAG_NOFREE;
    steam_http_req_send(sata->req);

    g_string_free(gstr, TRUE);
    g_hash_table_destroy(tbl);
}

void steam_api_summary(SteamApi *api, SteamFriendId *id,
                       SteamApiSummaryFunc func, gpointer data)
{
    SteamApiData *sata;

    g_return_if_fail(api != NULL);
    g_return_if_fail(id  != NULL);

    sata = steam_api_data_new(api, STEAM_API_TYPE_SUMMARY, func, data);
    steam_api_data_req(sata, STEAM_API_HOST, STEAM_API_PATH_SUMMARIES);

    steam_http_req_params_set(sata->req,
        STEAM_HTTP_PAIR("access_token", api->token),
        STEAM_HTTP_PAIR("steamids",     id->steam.s),
        NULL
    );

    steam_http_req_send(sata->req);
}
