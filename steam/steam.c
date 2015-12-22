/*
 * Copyright 2012-2015 James Geboski <jgeboski@gmail.com>
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

#include <stdarg.h>
#include <string.h>

#include "steam.h"
#include "steam-util.h"

#ifndef OPT_SELFMESSAGE
#define OPT_SELFMESSAGE 0
#endif

static void steam_cb_relogon(SteamApiReq *req, gpointer data);
static void steam_cb_msgs(SteamApiReq *req, gpointer data);
static void steam_cb_poll(SteamApiReq *req, gpointer data);
static void steam_cb_user_info_nicks(SteamApiReq *req, gpointer data);

/**
 * Creates a new #SteamData with an #account_t. The returned #SteamData
 * should be freed with #steam_data_free() when no longer needed.
 *
 * @param acc The #account_t.
 *
 * @return The #SteamData or NULL on error.
 **/
SteamData *steam_data_new(account_t *acc)
{
    SteamData *sata;

    g_return_val_if_fail(acc != NULL, NULL);

    sata = g_new0(SteamData, 1);
    sata->api = steam_api_new();
    sata->ic  = imcb_new(acc);
    sata->ic->proto_data = sata;

    sata->api->umqid  = g_strdup(set_getstr(&acc->set, "umqid"));
    sata->api->token  = g_strdup(set_getstr(&acc->set, "token"));
    sata->api->sessid = g_strdup(set_getstr(&acc->set, "sessid"));
    sata->game_status = set_getbool(&acc->set, "game_status");

    steam_api_rehash(sata->api);

    return sata;
}

/**
 * Frees all memory used by a #SteamData.
 *
 * @param sata The #SteamData.
 **/
void steam_data_free(SteamData *sata)
{
    if (G_UNLIKELY(sata == NULL))
        return;

    steam_api_free(sata->api);
    g_free(sata);
}

/**
 * Processes the error of a #SteamApiReq.
 *
 * @param sata   The #SteamData.
 * @param req    The #SteamApiReq.
 * @param logout TRUE to logout, otherwise FALSE.
 *
 * @return TRUE if an error exists, otherwise FALSE.
 **/
static gboolean steam_req_error(SteamData *sata, SteamApiReq *req,
                                gboolean logout)
{
    if (req->err == NULL)
        return FALSE;

    if (g_error_matches(req->err, STEAM_API_ERROR, STEAM_API_ERROR_EXPRIED)) {
        steam_util_debug_info("Relogging on due to expired session");
        steam_http_free_reqs(req->api->http);
        req = steam_api_req_new(req->api, steam_cb_relogon, sata);
        steam_api_req_logon(req);
        return TRUE;
    }

    if (g_error_matches(req->err, STEAM_HTTP_ERROR, STEAM_HTTP_ERROR_CLOSED)) {
        steam_util_debug_warn("Request (%p) forcefully closed", req->req);
        /* Ignore closed HTTP connections */
        return TRUE;
    }

    steam_util_debug_error("Error: %s", req->err->message);
    imcb_error(sata->ic, "%s", req->err->message);

    if (logout) {
        steam_util_debug_info("Reconnecting due to error");
        imc_logout(sata->ic, logout);
    }

    return TRUE;
}


/**
 * Updates the status of a #bee_user_t based on a #SteamUserInfo.
 *
 * @param sata The #SteamData.
 * @param info The #SteamUserInfo.
 * @param bu   The #bee_user_t or NULL.
 **/
static void steam_user_status(SteamData *sata, const SteamUserInfo *info,
                              bee_user_t *bu)
{
    SteamUser   *user;
    const gchar *m;
    gchar       *game;
    gint         f;
    gboolean     cgm;
    gboolean     csv;
    gchar        sid[STEAM_ID_STR_MAX];

    STEAM_ID_STR(info->id, sid);

    if (bu == NULL) {
        bu = imcb_buddy_by_handle(sata->ic, sid);

        if (G_UNLIKELY(bu == NULL))
            return;
    }

    if (info->state == STEAM_USER_STATE_OFFLINE) {
        imcb_buddy_status(sata->ic, sid, 0, NULL, NULL);
        return;
    }

    f = BEE_USER_ONLINE;
    m = steam_user_state_str(info->state);

    if (info->state != STEAM_USER_STATE_ONLINE)
        f |= BEE_USER_AWAY;

    if (info->game != NULL)
        f |= BEE_USER_SPECIAL;

    user = bu->data;
    cgm  = g_strcmp0(info->game,   user->game)   != 0;
    csv  = g_strcmp0(info->server, user->server) != 0;

    if (!cgm && !csv) {
        imcb_buddy_status(sata->ic, sid, f, m, bu->status_msg);
        return;
    }

    if (info->server != NULL)
        game = g_strdup_printf("%s (%s)", info->game, info->server);
    else
        game = g_strdup(info->game);

    if (cgm) {
        g_free(user->game);
        user->game = g_strdup(info->game);
    }

    if (csv) {
        g_free(user->server);
        user->server = g_strdup(info->server);
    }

    if (sata->game_status && (game != NULL))
        steam_user_chans_msg(user, "/me is now playing: %s", game);

    imcb_buddy_status(sata->ic, sid, f, m, game);
    g_free(game);
}

/**
 * Processes a #SteamApiMsg.
 *
 * @param sata The #SteamData.
 * @param msg  The #SteamUserMsg.
 * @param time The timestamp (UTC) of the message, or 0 for now.
 **/
static void steam_user_msg(SteamData *sata, SteamUserMsg *msg, gint64 time)
{
    SteamUserInfo *info = msg->info;
    bee_user_t    *bu;
    gchar         *str;
    guint32        f;
    gchar          sid[STEAM_ID_STR_MAX];

    STEAM_ID_STR(info->id, sid);
    steam_util_debug_info("Incoming message from %s (Type: %u, Act: %u)",
                          sid, msg->type, info->act);

    switch (msg->type) {
    case STEAM_USER_MSG_TYPE_MY_EMOTE:
    case STEAM_USER_MSG_TYPE_MY_SAYTEXT:
        if (set_find(&sata->ic->bee->set, "self_messages") == NULL)
            return;

        if (msg->type == STEAM_USER_MSG_TYPE_MY_EMOTE)
            str = g_strconcat("/me ", msg->text, NULL);
        else
            str = g_strdup(msg->text);

        imcb_buddy_msg(sata->ic, sid, str, OPT_SELFMESSAGE, time);
        g_free(str);
        return;

    case STEAM_USER_MSG_TYPE_EMOTE:
    case STEAM_USER_MSG_TYPE_SAYTEXT:
        bu = imcb_buddy_by_handle(sata->ic, sid);

        if ((bu != NULL) && (bu->flags & OPT_TYPING))
            imcb_buddy_typing(sata->ic, sid, 0);

        if (msg->type == STEAM_USER_MSG_TYPE_EMOTE)
            str = g_strconcat("/me ", msg->text, NULL);
        else
            str = g_strdup(msg->text);

        imcb_buddy_msg(sata->ic, sid, str, 0, time);
        g_free(str);
        return;

    case STEAM_USER_MSG_TYPE_LEFT_CONV:
        imcb_buddy_typing(sata->ic, sid, 0);
        return;

    case STEAM_USER_MSG_TYPE_RELATIONSHIP:
        goto relationship;

    case STEAM_USER_MSG_TYPE_TYPING:
        bu = imcb_buddy_by_handle(sata->ic, sid);

        if (G_UNLIKELY(bu == NULL))
            return;

        f = (bu->flags & OPT_TYPING) ? 0 : OPT_TYPING;
        imcb_buddy_typing(sata->ic, sid, f);
        return;

    default:
        steam_user_status(sata, info, NULL);
        return;
    }

relationship:
    switch (info->act) {
    case STEAM_USER_ACT_REMOVE:
    case STEAM_USER_ACT_IGNORE:
        imcb_remove_buddy(sata->ic, sid, NULL);
        return;

    case STEAM_USER_ACT_REQUEST:
        imcb_ask_auth(sata->ic, sid, info->nick);
        return;

    case STEAM_USER_ACT_ADD:
        imcb_add_buddy(sata->ic, sid, NULL);
        imcb_buddy_nick_hint(sata->ic, sid, info->nick);
        imcb_rename_buddy(sata->ic, sid, info->fullname);
        steam_user_status(sata, info, NULL);
        return;

    default:
        return;
    }
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_auth().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_auth(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;
    account_t *acc;
    gchar     *str;

    acc = sata->ic->acc;

    set_setstr(&acc->set, "cgid",   req->api->cgid);
    set_setstr(&acc->set, "esid",   req->api->esid);
    set_setstr(&acc->set, "sessid", req->api->sessid);
    set_setstr(&acc->set, "token",  req->api->token);

    if (steam_req_error(sata, req, FALSE)) {
        if (req->err->domain != STEAM_API_ERROR) {
            imc_logout(sata->ic, FALSE);
            return;
        }

        switch (req->err->code) {
        case STEAM_API_ERROR_CAPTCHA:
            str = steam_api_captcha_url(req->api->cgid);
            imcb_log(sata->ic, "View: %s", str);
            imcb_log(sata->ic, "Run: account %s set captcha <text>", acc->tag);
            g_free(str);
            break;

        case STEAM_API_ERROR_STEAMGUARD:
            imcb_log(sata->ic, "Run: account %s set authcode <code>", acc->tag);
            break;
        }

        imc_logout(sata->ic, FALSE);
        return;
    }

    steam_api_free_auth(req->api);

    imcb_log(sata->ic, "Authentication finished");
    account_off(acc->bee, acc);
    account_on(acc->bee, acc);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_friends().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_friends(SteamApiReq *req, gpointer data)
{
    SteamData            *sata = data;
    SteamUserInfo        *info;
    SteamUser            *user;
    struct im_connection *ic;
    GList                *l;
    bee_user_t           *bu;
    gchar                 sid[STEAM_ID_STR_MAX];

    if (steam_req_error(sata, req, TRUE))
        return;

    ic = sata->ic;

    if (!(ic->flags & BEE_USER_ONLINE))
        imcb_connected(ic);

    for (l = req->infs->head; l != NULL; l = l->next) {
        info = l->data;
        STEAM_ID_STR(info->id, sid);

        /* Attempt to grab the buddy before adding */
        bu = bee_user_by_handle(sata->ic->bee, sata->ic, sid);

        if (bu == NULL) {
            imcb_add_buddy(sata->ic, sid, NULL);
            imcb_buddy_nick_hint(sata->ic, sid, info->nick);
            imcb_rename_buddy(sata->ic, sid, info->fullname);
        }

        bu = bee_user_by_handle(sata->ic->bee, sata->ic, sid);

        if (G_UNLIKELY(bu == NULL))
            continue;

        user = bu->data;
        user->vtime = info->vtime;

        switch (info->rel) {
        case STEAM_USER_REL_FRIEND:
            steam_user_status(sata, info, bu);
            break;

        case STEAM_USER_REL_IGNORE:
            ic->deny = g_slist_prepend(ic->deny, g_strdup(bu->handle));
            break;
        }

        if (info->unread > 0) {
            req = steam_api_req_new(req->api, steam_cb_msgs, sata);
            steam_api_req_msgs(req, info->id, info->vtime);
        }
    }

    req = steam_api_req_new(req->api, steam_cb_poll, sata);
    steam_api_req_poll(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_key().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_key(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;
    account_t *acc;
    gchar     *ac;
    gchar     *cc;

    if (steam_req_error(sata, req, TRUE))
        return;

    acc = sata->ic->acc;
    ac  = set_getstr(&acc->set, "authcode");
    cc  = set_getstr(&acc->set, "captcha");

    imcb_log(sata->ic, "Requesting authentication token");

    req = steam_api_req_new(req->api, steam_cb_auth, sata);
    steam_api_req_auth(req, acc->user, acc->pass, ac, cc);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_logoff().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_logoff(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    steam_data_free(sata);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_logon().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_logon(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    if (steam_req_error(sata, req, TRUE))
        return;

    set_setstr(&sata->ic->acc->set, "umqid", req->api->umqid);
    imcb_log(sata->ic, "Requesting friends list");

    req = steam_api_req_new(req->api, steam_cb_friends, sata);
    steam_api_req_friends(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_logon() for relogging.
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_relogon(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    if (steam_req_error(sata, req, TRUE))
        return;

    steam_util_debug_info("Relogon completed");

    /* Update the friend list for good measures */
    req = steam_api_req_new(req->api, steam_cb_friends, sata);
    steam_api_req_friends(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_msg().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_msg(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;
    steam_req_error(sata, req, TRUE);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_msgs().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_msgs(SteamApiReq *req, gpointer data)
{
    SteamData      *sata = data;
    SteamUser      *user;
    SteamUserInfo  *info;
    SteamUserMsg   *msg;
    bee_user_t     *bu;
    GList          *l;
    gchar           sid[STEAM_ID_STR_MAX];

    if (steam_req_error(sata, req, TRUE))
        return;

    for (bu = NULL, l = req->msgs->head; l != NULL; l = l->next) {
        msg  = l->data;
        info = msg->info;
        STEAM_ID_STR(info->id, sid);

        if ((bu == NULL) || (g_strcmp0(sid, bu->handle) != 0)) {
            bu = bee_user_by_handle(sata->ic->bee, sata->ic, sid);

            if (G_UNLIKELY(bu == NULL))
                continue;

            user = bu->data;
        }

        if (msg->time > user->vtime)
            steam_user_msg(sata, msg, msg->time);
    }
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_poll().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_poll(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;
    GList     *l;

    if (steam_req_error(sata, req, TRUE))
        return;

    for (l = req->msgs->head; l != NULL; l = l->next)
        steam_user_msg(sata, l->data, 0);

    req = steam_api_req_new(req->api, steam_cb_poll, sata);
    steam_api_req_poll(req);
}

/**
 * Implemented #SteamApiFunc for generic users actions.
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_user_action(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info = req->infs->head->data;

    if (steam_req_error(sata, req, TRUE))
        return;

    steam_user_status(sata, info, NULL);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_info().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_user_info(SteamApiReq *req, gpointer data)
{
    req = steam_api_req_fwd(req);

    req->func = steam_cb_user_info_nicks;
    steam_api_req_user_info_nicks(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_info_nicks().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_user_info_nicks(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info = req->infs->head->data;
    const gchar   *ctr;
    gchar         *str;
    GSList        *l;
    guint          i;

    if (steam_req_error(sata, req, TRUE))
        return;

    if (info->fullname != NULL)
        imcb_log(sata->ic, "Name: %s (%s)", info->nick, info->fullname);
    else
        imcb_log(sata->ic, "Name: %s", info->nick);

    if (info->game != NULL) {
        if (info->server != NULL) {
            imcb_log(sata->ic, "Playing: %s - steam://connect/%s",
                     info->game, info->server);
        } else {
            imcb_log(sata->ic, "Playing: %s", info->game);
        }
    }

    ctr = steam_user_state_str(info->state);

    if (info->state == STEAM_USER_STATE_OFFLINE)
        str = steam_util_time_since_utc(info->ltime);
    else
        str = steam_user_flags_str(info->flags);

    if (str != NULL) {
        imcb_log(sata->ic, "Status: %s (%s)", ctr, str);
        g_free(str);
    } else {
        imcb_log(sata->ic, "Status: %s", ctr);
    }

    imcb_log(sata->ic, "Steam ID: %" STEAM_ID_FORMAT " (%" G_GINT32_FORMAT ")",
             info->id, STEAM_ID_ACCID(info->id));

    if (info->profile != NULL)
        imcb_log(sata->ic, "Profile: %s", info->profile);

    if (info->nicks != NULL) {
        imcb_log(sata->ic, "Nicknames:");

        for (l = info->nicks, i = 1; l != NULL; l = l->next, i++)
            imcb_log(sata->ic, "%u. `%s'", i, (gchar*) l->data);
    }

    steam_user_status(sata, info, NULL);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_search().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_cb_user_search(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info;
    const gchar   *tag;
    GList         *l;
    guint          i;
    gchar          sid[STEAM_ID_STR_MAX];

    if (steam_req_error(sata, req, TRUE))
        return;

    for (l = req->infs->head, i = 0; (l != NULL) && (i < 2); l = l->next, i++);

    switch (i) {
    case 0:
        imcb_error(sata->ic, "Failed to find any friend(s)");
        return;

    case 1:
        info = req->infs->head->data;
        req  = steam_api_req_new(req->api, steam_cb_user_action, sata);
        steam_api_req_user_add(req, info->id);
        return;
    }

    imcb_log(sata->ic, "Select from one of the following Steam Friends:");
    tag = sata->ic->acc->tag;

    for (l = req->infs->head, i = 1; l != NULL; l = l->next, i++) {
        info = l->data;
        STEAM_ID_STR(info->id, sid);

        imcb_log(sata->ic, "%u. `%s' %s", i, info->nick, info->profile);
        imcb_log(sata->ic, "-- add %s steamid:%s", tag, sid);
    }
}

/**
 * Implemented #set_eval for generic accounton operations. This simply
 * turns the account on as soon a value is set if it is not already
 * turned on.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_accounton(set_t *set, char *value)
{
    account_t *acc = set->data;

    if ((acc->ic != NULL) && (acc->ic->flags & BEE_USER_ONLINE))
        return value;

    /* Some hackery to auto connect upon authcode entry */

    g_free(set->value);
    set->value = g_strdup(value);

    account_on(acc->bee, acc);

    g_free(set->value);
    set->value = NULL;

    return value;
}

/**
 * Implemented #set_eval for the set of game_status.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_game_status(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sata;

    if (!is_bool(value))
        return SET_INVALID;

    if (acc->ic == NULL)
        return value;

    sata = acc->ic->proto_data;
    sata->game_status = bool2int(value);

    return value;
}

/**
 * Implemented #set_eval for the set of password. If the account is on,
 * this disables the account, and resets the token. Then the plugin
 * will force the authentication process with the new password.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_password(set_t *set, char *value)
{
    account_t *acc = set->data;

    value = set_eval_account(set, value);
    set_reset(&acc->set, "token");

    if (acc->ic != NULL) {
        account_off(acc->bee, acc);
        account_on(acc->bee, acc);
    } else if (acc->reconnect != 0) {
        account_on(acc->bee, acc);
    }

    return value;
}

/**
 * Implements #prpl->init(). This initializes the an account.
 *
 * @param acc The #account_t.
 **/
static void steam_init(account_t *acc)
{
    set_t *s;

    s = set_add(&acc->set, "authcode", NULL, steam_eval_accounton, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_NOSAVE;

    s = set_add(&acc->set, "captcha", NULL, steam_eval_accounton, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_NOSAVE;

    s = set_add(&acc->set, "esid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_NOSAVE;

    s = set_add(&acc->set, "cgid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_NOSAVE;

    s = set_add(&acc->set, "umqid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "token", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

    s = set_add(&acc->set, "sessid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

    set_add(&acc->set, "game_status", "false", steam_eval_game_status, acc);
    set_add(&acc->set, "password", NULL, steam_eval_password, acc);
}

/**
 * Implements #prpl->login(). This logins an account in.
 *
 * @param acc The #account_t.
 **/
static void steam_login(account_t *acc)
{
    SteamData   *sata;
    SteamApiReq *req;
    gchar       *str;

    sata = steam_data_new(acc);
    imcb_log(sata->ic, "Connecting");

    if ((sata->api->token == NULL) || (sata->api->sessid == NULL)) {
        str = set_getstr(&acc->set, "cgid");
        g_free(sata->api->cgid);
        sata->api->cgid = g_strdup(str);

        str = set_getstr(&acc->set, "esid");
        g_free(sata->api->esid);
        sata->api->esid = g_strdup(str);

        imcb_log(sata->ic, "Requesting authentication key");
        req = steam_api_req_new(sata->api, steam_cb_key, sata);
        steam_api_req_key(req, acc->user);
        return;
    }

    imcb_log(sata->ic, "Sending logon request");
    req = steam_api_req_new(sata->api, steam_cb_logon, sata);
    steam_api_req_logon(req);
}

/**
 * Implements #prpl->logout(). This logs an account out.
 *
 * @param ic The #im_connection.
 **/
static void steam_logout(struct im_connection *ic)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    steam_http_free_reqs(sata->api->http);

    if (ic->flags & BEE_USER_ONLINE) {
        req = steam_api_req_new(sata->api, steam_cb_logoff, sata);
        steam_api_req_logoff(req);
    } else {
        steam_data_free(sata);
    }
}

/**
 * Implements #prpl->buddy_msg(). This sends a message to a buddy.
 *
 * @param ic      The #im_connection.
 * @param to      The handle of the buddy.
 * @param message The message to send.
 * @param flags   The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbe does nothing with this)
 **/
static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    SteamData    *sata = ic->proto_data;
    SteamApiReq  *req;
    SteamUserMsg *msg;

    msg = steam_user_msg_new(STEAM_ID_NEW_STR(to));
    msg->type = STEAM_USER_MSG_TYPE_SAYTEXT;
    msg->text = g_strdup(message);

    /* As of January 23, 2013, Valve has disabled support for /me. It
     * was disabled as it "allowed some users to modify the color of
     * their chat text."
     *
     * See the ChangeLog for more information: http://goo.gl/TETV5
     */

    /*
    if (g_str_has_prefix(message, "/me")) {
        if (strlen(message) < 5)
            return 0;

        msg->type = STEAM_USER_MSG_TYPE_EMOTE;
        msg->text = g_strdup(message + 4);
    } else {
        msg->type = STEAM_USER_MSG_TYPE_SAYTEXT;
        msg->text = g_strdup(message);
    }
    */

    req = steam_api_req_new(sata->api, steam_cb_msg, sata);
    steam_api_req_msg(req, msg);

    steam_user_msg_free(msg);
    return 0;
}

/**
 * Implements #prpl->set_away(). This sets the away state of the user.
 *
 * @param ic      The #im_connection.
 * @param state   The away state.
 * @param message The away message.
 **/
static void steam_set_away(struct im_connection *ic, char *state, char *message)
{
    SteamData *sata = ic->proto_data;

    if (g_strcmp0(state, "Away") == 0)
        sata->api->info->state = STEAM_USER_STATE_AWAY;
    else if (g_strcmp0(state, "Snooze") == 0)
        sata->api->info->state = STEAM_USER_STATE_SNOOZE;
    else
        sata->api->info->state = STEAM_USER_STATE_ONLINE;
}

/**
 * Implements #prpl->send_typing(). This sends the typing state message.
 *
 * @param ic    The #im_connection.
 * @param who   The handle of the buddy.
 * @param flags The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbe does nothing with this)
 **/
static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    SteamData    *sata = ic->proto_data;
    SteamApiReq  *req;
    SteamUserMsg *msg;

    msg = steam_user_msg_new(STEAM_ID_NEW_STR(who));
    msg->type = STEAM_USER_MSG_TYPE_TYPING;

    req = steam_api_req_new(sata->api, steam_cb_msg, sata);
    steam_api_req_msg(req, msg);

    steam_user_msg_free(msg);
    return 0;
}

/**
 * Implements #prpl->add_buddy(). This adds a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void steam_add_buddy(struct im_connection *ic, char *name, char *group)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;
    gchar       *str;

    if (g_ascii_strncasecmp(name, "steamid:", 8) != 0) {
        req = steam_api_req_new(sata->api, steam_cb_user_search, sata);
        steam_api_req_user_search(req, name, 5);
        return;
    }

    str = strchr(name, ':');

    if ((str != NULL) && ((++str)[0] != 0)) {
        req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
        steam_api_req_user_add(req, STEAM_ID_NEW_STR(str));
    } else {
        imcb_error(sata->ic, "No Steam ID specified");
    }
}

/**
 * Implements #prpl->remove_buddy(). This removes a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char *group)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
    steam_api_req_user_remove(req, STEAM_ID_NEW_STR(name));
}

/**
 * Implements #prpl->add_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_add_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->add_deny(). This blocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_add_deny(struct im_connection *ic, char *who)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    imcb_buddy_status(ic, who, 0, NULL, NULL);
    req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
    steam_api_req_user_ignore(req, STEAM_ID_NEW_STR(who), TRUE);
}

/**
 * Implements #prpl->rem_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_rem_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->rem_deny(). This unblocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_rem_deny(struct im_connection *ic, char *who)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
    steam_api_req_user_ignore(req, STEAM_ID_NEW_STR(who), FALSE);
}

/**
 * Implements #prpl->get_info(). This retrieves the info of a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_get_info(struct im_connection *ic, char *who)
{
    SteamData     *sata = ic->proto_data;
    SteamApiReq   *req;
    SteamUserInfo *info;

    info = steam_user_info_new(STEAM_ID_NEW_STR(who));
    req  = steam_api_req_new(sata->api, steam_cb_user_info, sata);

    g_queue_push_head(req->infs, info);
    steam_api_req_user_info(req);
}

/**
 * Implements #prpl->away_states(). This retrieves the away states.
 *
 * @param ic The #im_connection.
 *
 * @return The #GList of away states.
 **/
static GList *steam_away_states(struct im_connection *ic)
{
    static GList *states = NULL;

    if (G_UNLIKELY(states == NULL)) {
        /* Steam only support setting "Away" and "Snooze" */
        states = g_list_prepend(states, "Snooze");
        states = g_list_prepend(states, "Away");
    }

    return states;
}

/**
 * Implements #prpl->auth_allow(). This accepts buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_auth_allow(struct im_connection *ic, const char *who)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
    steam_api_req_user_accept(req, STEAM_ID_NEW_STR(who),
                              STEAM_API_ACCEPT_TYPE_DEFAULT);
}

/**
 * Implements #prpl->auth_allow(). This denies buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void steam_auth_deny(struct im_connection *ic, const char *who)
{
    SteamData   *sata = ic->proto_data;
    SteamApiReq *req;

    req = steam_api_req_new(sata->api, steam_cb_user_action, sata);
    steam_api_req_user_accept(req, STEAM_ID_NEW_STR(who),
                              STEAM_API_ACCEPT_TYPE_IGNORE);
}

/**
 * Implements #prpl->buddy_data_add(). This adds data to the buddy.
 *
 * @param bu The #bee_user_t.
 **/
static void steam_buddy_data_add(struct bee_user *bu)
{
    bu->data = steam_user_new(bu);
}

/**
 * Implements #prpl->buddy_data_free(). This frees the buddy data.
 *
 * @param bu The #bee_user_t.
 **/
static void steam_buddy_data_free(struct bee_user *bu)
{
    steam_user_free(bu->data);
}

void init_plugin(void);

/**
 * Implements the #init_plugin() function. BitlBee looks for this
 * function and executes it to register the protocol and its related
 * callbacks.
 **/
void init_plugin()
{
    struct prpl *pp;

    pp = g_new0(struct prpl, 1);

    pp->name            = "steam";
    pp->options         = OPT_NOOTR;
    pp->init            = steam_init;
    pp->login           = steam_login;
    pp->logout          = steam_logout;
    pp->buddy_msg       = steam_buddy_msg;
    pp->set_away        = steam_set_away;
    pp->send_typing     = steam_send_typing;
    pp->add_buddy       = steam_add_buddy;
    pp->remove_buddy    = steam_remove_buddy;
    pp->add_permit      = steam_add_permit;
    pp->add_deny        = steam_add_deny;
    pp->rem_permit      = steam_rem_permit;
    pp->rem_deny        = steam_rem_deny;
    pp->get_info        = steam_get_info;
    pp->away_states     = steam_away_states;
    pp->handle_cmp      = g_ascii_strcasecmp;
    pp->auth_allow      = steam_auth_allow;
    pp->auth_deny       = steam_auth_deny;
    pp->buddy_data_add  = steam_buddy_data_add;
    pp->buddy_data_free = steam_buddy_data_free;

    register_protocol(pp);
}
