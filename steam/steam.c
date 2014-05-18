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

#include <stdarg.h>
#include <string.h>

#include "steam.h"

static void steam_logon(SteamApiReq *req, gpointer data);
static void steam_relogon(SteamApiReq *req, gpointer data);
static void steam_poll(SteamApiReq *req, gpointer data);
static void steam_user_chatlog(SteamApiReq *req, gpointer data);

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
    gchar     *str;

    g_return_val_if_fail(acc != NULL, NULL);

    sata = g_new0(SteamData, 1);

    sata->ic = imcb_new(acc);
    sata->ic->proto_data = sata;

    str = set_getstr(&acc->set, "umqid");
    sata->api = steam_api_new(str);

    sata->api->token   = g_strdup(set_getstr(&acc->set, "token"));
    sata->api->sessid  = g_strdup(set_getstr(&acc->set, "sessid"));
    sata->game_status  = set_getbool(&acc->set, "game_status");

    str = set_getstr(&acc->set, "show_playing");
    sata->show_playing = steam_user_chan_mode(str);

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
        steam_http_free_reqs(req->api->http);
        req = steam_api_req_new(req->api, steam_relogon, sata);
        steam_api_req_logon(req);
        return TRUE;
    }

    if (g_error_matches(req->err, STEAM_HTTP_ERROR, STEAM_HTTP_ERROR_CLOSED)) {
        /* Ignore closed HTTP connections */
        return TRUE;
    }

    imcb_error(sata->ic, "%s", req->err->message);

    if (logout)
        imc_logout(sata->ic, logout);

    return TRUE;
}


/**
 * Updates the status of a #bee_user_t based on a #SteamUserInfo.
 *
 * @param sata The #SteamData.
 * @param info The #SteamUserInfo.
 * @param bu   The #bee_user_t.
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

    if (info->state == STEAM_USER_STATE_OFFLINE) {
        imcb_buddy_status(sata->ic, info->id->steam.s, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_user_state_str(info->state);

    if (info->state != STEAM_USER_STATE_ONLINE)
        f |= OPT_AWAY;

    user = bu->data;
    cgm  = g_strcmp0(info->game,   user->game)   != 0;
    csv  = g_strcmp0(info->server, user->server) != 0;

    if (!cgm && !csv) {
        if (user->game == NULL) {
            imcb_buddy_status(sata->ic, info->id->steam.s, f, m,
                              bu->status_msg);
        }

        return;
    }

    if (info->server != NULL)
        game = g_strdup_printf("%s (%s)", info->game, info->server);
    else
        game = g_strdup(info->game);

    if (cgm) {
        imcb_buddy_status(sata->ic, info->id->steam.s, f, m, game);

        if (info->game != NULL)
            steam_user_chans_umode(user, sata->show_playing, TRUE);

        g_free(user->game);
        user->game = g_strdup(info->game);
    }

    if (csv) {
        g_free(user->server);
        user->server = g_strdup(info->server);
    }

    if (sata->game_status && (game != NULL))
        steam_user_chans_msg(user, "/me is now playing: %s", game);

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

    switch (msg->type) {
    case STEAM_USER_MSG_TYPE_EMOTE:
    case STEAM_USER_MSG_TYPE_SAYTEXT:
        bu = imcb_buddy_by_handle(sata->ic, info->id->steam.s);

        if ((bu != NULL) && (bu->flags & OPT_TYPING))
            imcb_buddy_typing(sata->ic, info->id->steam.s, 0);

        if (msg->type == STEAM_USER_MSG_TYPE_EMOTE)
            str = g_strconcat("/me ", msg->text, NULL);
        else
            str = g_strdup(msg->text);

        imcb_buddy_msg(sata->ic, info->id->steam.s, str, 0, time);
        g_free(str);
        return;

    case STEAM_USER_MSG_TYPE_LEFT_CONV:
        imcb_buddy_typing(sata->ic, info->id->steam.s, 0);
        return;

    case STEAM_USER_MSG_TYPE_RELATIONSHIP:
        goto relationship;

    case STEAM_USER_MSG_TYPE_TYPING:
        bu = imcb_buddy_by_handle(sata->ic, info->id->steam.s);

        if (G_UNLIKELY(bu == NULL))
            return;

        f = (bu->flags & OPT_TYPING) ? 0 : OPT_TYPING;
        imcb_buddy_typing(sata->ic, info->id->steam.s, f);
        return;

    default:
        bu = imcb_buddy_by_handle(sata->ic, info->id->steam.s);

        if (G_UNLIKELY(bu == NULL))
            return;

        steam_user_status(sata, info, bu);
        return;
    }

relationship:
    switch (info->act) {
    case STEAM_USER_ACT_REMOVE:
    case STEAM_USER_ACT_IGNORE:
        imcb_remove_buddy(sata->ic, info->id->steam.s, NULL);
        return;

    case STEAM_USER_ACT_REQUEST:
        imcb_ask_auth(sata->ic, info->id->steam.s, info->nick);
        return;

    case STEAM_USER_ACT_ADD:
        imcb_add_buddy(sata->ic, info->id->steam.s, NULL);
        imcb_buddy_nick_hint(sata->ic, info->id->steam.s, info->nick);
        imcb_rename_buddy(sata->ic, info->id->steam.s, info->fullname);

        bu = imcb_buddy_by_handle(sata->ic, info->id->steam.s);
        steam_user_status(sata, info, bu);
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
static void steam_auth(SteamApiReq *req, gpointer data)
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
    imcb_log(sata->ic, "Sending login request");

    req = steam_api_req_new(req->api, steam_logon, sata);
    steam_api_req_logon(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_friends().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_friends(SteamApiReq *req, gpointer data)
{
    SteamData            *sata = data;
    SteamUserInfo        *info;
    SteamUser            *user;
    struct im_connection *ic;
    GList                *l;
    bee_user_t           *bu;

    if (steam_req_error(sata, req, TRUE))
        return;

    ic = sata->ic;

    if (!(ic->flags & OPT_LOGGED_IN))
        imcb_connected(ic);

    for (l = req->infs->head; l != NULL; l = l->next) {
        info = l->data;

        /* Attempt to grab the buddy before adding */
        bu = bee_user_by_handle(sata->ic->bee, sata->ic, info->id->steam.s);

        if (bu == NULL) {
            imcb_add_buddy(sata->ic, info->id->steam.s, NULL);
            imcb_buddy_nick_hint(sata->ic, info->id->steam.s, info->nick);
            imcb_rename_buddy(sata->ic, info->id->steam.s, info->fullname);
        }

        bu = bee_user_by_handle(sata->ic->bee, sata->ic, info->id->steam.s);

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

        if (info->mtime > info->vtime) {
            req = steam_api_req_new(req->api, steam_user_chatlog, sata);
            steam_api_req_user_chatlog(req, info->id);
        }
    }

    req = steam_api_req_new(req->api, steam_poll, sata);
    steam_api_req_poll(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_key().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_key(SteamApiReq *req, gpointer data)
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

    req = steam_api_req_new(req->api, steam_auth, sata);
    steam_api_req_auth(req, acc->user, acc->pass, ac, cc);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_logoff().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_logoff(SteamApiReq *req, gpointer data)
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
static void steam_logon(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    if (steam_req_error(sata, req, TRUE))
        return;

    set_setstr(&sata->ic->acc->set, "umqid", req->api->umqid);
    imcb_log(sata->ic, "Requesting friends list");

    steam_api_refresh(req->api);

    req = steam_api_req_new(req->api, steam_friends, sata);
    steam_api_req_friends(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_logon() for relogging.
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_relogon(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    if (steam_req_error(sata, req, TRUE))
        return;

    steam_api_refresh(req->api);

    /* Update the friend list for good measures */
    req = steam_api_req_new(req->api, steam_friends, sata);
    steam_api_req_friends(req);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_msg().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_msg(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;

    if (steam_req_error(sata, req, TRUE))
        return;
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_poll().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_poll(SteamApiReq *req, gpointer data)
{
    SteamData *sata = data;
    GList     *l;

    if (steam_req_error(sata, req, TRUE))
        return;

    for (l = req->msgs->head; l != NULL; l = l->next)
        steam_user_msg(sata, l->data, 0);

    req = steam_api_req_new(req->api, steam_poll, sata);
    steam_api_req_poll(req);
}

/**
 * Implemented #SteamApiFunc for generic users actions.
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_user_action(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info = req->infs->head->data;
    bee_user_t    *bu;

    if (steam_req_error(sata, req, TRUE))
        return;

    bu = bee_user_by_handle(sata->ic->bee, sata->ic, info->id->steam.s);

    if (bu != NULL)
        steam_user_status(sata, info, bu);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_chatlog().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_user_chatlog(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUser     *user;
    SteamUserInfo *info;
    SteamUserMsg  *msg;
    bee_user_t    *bu;
    GList         *l;

    if (steam_req_error(sata, req, TRUE))
        return;

    for (bu = NULL, l = req->msgs->head; l != NULL; l = l->next) {
        msg  = l->data;
        info = msg->info;

        if ((bu == NULL) || (g_strcmp0(info->id->steam.s, bu->handle) != 0)) {
            bu = bee_user_by_handle(sata->ic->bee, sata->ic, info->id->steam.s);

            if (G_UNLIKELY(bu == NULL))
                continue;

            user = bu->data;
        }

        if (msg->time > user->vtime)
            steam_user_msg(sata, msg, msg->time);
    }
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_info().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_user_info(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info = req->infs->head->data;
    bee_user_t    *bu;
    const gchar   *ctr;
    gchar         *str;

    if (steam_req_error(sata, req, TRUE))
        return;

    bu = bee_user_by_handle(sata->ic->bee, sata->ic, info->id->steam.s);

    if (G_LIKELY(bu == NULL))
        steam_user_status(sata, info, bu);

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
    str = steam_user_flags_str(info->flags);

    if (str != NULL) {
        imcb_log(sata->ic, "Status: %s (%s)", ctr, str);
        g_free(str);
    } else {
        imcb_log(sata->ic, "Status: %s", ctr);
    }

    imcb_log(sata->ic, "Steam ID: %s (%s)", info->id->steam.s,
             info->id->commu.s);

    str = steam_api_profile_url(info->id);
    imcb_log(sata->ic, "Profile: %s", str);
    g_free(str);
}

/**
 * Implemented #SteamApiFunc for #steam_api_req_user_search().
 *
 * @param req  The #SteamApiReq.
 * @param data The user defined data, which is #SteamData.
 **/
static void steam_user_search(SteamApiReq *req, gpointer data)
{
    SteamData     *sata = data;
    SteamUserInfo *info;
    const gchar   *tag;
    GList         *l;
    gchar         *str;
    guint          i;

    if (steam_req_error(sata, req, TRUE))
        return;

    for (l = req->infs->head, i = 0; (l != NULL) && (i < 2); l = l->next, i++);

    switch (i) {
    case 0:
        imcb_error(sata->ic, "Failed to find any friend(s)");
        return;

    case 1:
        info = req->infs->head->data;
        req  = steam_api_req_new(req->api, steam_user_action, sata);
        steam_api_req_user_add(req, info->id);
        return;
    }

    imcb_log(sata->ic, "Select from one of the following Steam Friends:");
    tag = sata->ic->acc->tag;

    for (l = req->infs->head, i = 1; l != NULL; l = l->next, i++) {
        info = l->data;
        str  = steam_api_profile_url(info->id);

        imcb_log(sata->ic, "%u. `%s' %s", i, info->nick, str);
        imcb_log(sata->ic, "-- add %s steamid:%s", tag, info->id->steam.s);

        g_free(str);
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

    if ((acc->ic != NULL) && (acc->ic->flags & OPT_LOGGED_IN))
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
 * Implemented #set_eval for the set of show_playing. If the account
 * is on, this updates all buddies in all channels that are currently
 * in a game with the new user mode.
 *
 * @param set   The #set_t.
 * @param value The set value.
 *
 * @return The resulting set value.
 **/
static char *steam_eval_show_playing(set_t *set, char *value)
{
    account_t  *acc = set->data;
    SteamData  *sata;
    SteamUser  *user;
    bee_user_t *bu;
    GSList     *l;
    gint        sply;

    if ((acc->ic == NULL) || (acc->ic->proto_data == NULL))
        return value;

    if (G_UNLIKELY(g_strcmp0(acc->prpl->name, "steam") != 0)) {
        g_warn_if_reached();
        return value;
    }

    sata = acc->ic->proto_data;
    sply = steam_user_chan_mode(value);

    if (sply == sata->show_playing)
        return value;

    sata->show_playing = sply;

    for (l = acc->bee->users; l; l = l->next) {
        bu   = l->data;
        user = bu->data;

        if (G_UNLIKELY((bu->ic != acc->ic) || (user == NULL))) {
            g_warn_if_reached();
            continue;
        }

        if (!(bu->flags & BEE_USER_ONLINE) || (user->game == NULL))
            continue;

        imcb_buddy_status(acc->ic, bu->handle, bu->flags,
                          bu->status, bu->status_msg);
        steam_user_chans_umode(user, sata->show_playing, TRUE);
    }

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

    s = set_add(&acc->set, "show_playing", "%", steam_eval_show_playing, acc);
    s->flags = SET_NULL_OK;

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

    if ((sata->api->token != NULL) && (sata->api->sessid != NULL)) {
        imcb_log(sata->ic, "Sending logon request");

        req = steam_api_req_new(sata->api, steam_logon, sata);
        steam_api_req_logon(req);
        return;
    }

    str = set_getstr(&acc->set, "cgid");
    g_free(sata->api->cgid);
    sata->api->cgid = g_strdup(str);

    str = set_getstr(&acc->set, "esid");
    g_free(sata->api->esid);
    sata->api->esid = g_strdup(str);

    imcb_log(sata->ic, "Requesting authentication key");

    req = steam_api_req_new(sata->api, steam_key, sata);
    steam_api_req_key(req, acc->user);
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

    if (ic->flags & OPT_LOGGED_IN) {
        req = steam_api_req_new(sata->api, steam_logoff, sata);
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

    msg = steam_user_msg_new_str(to);
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

    req = steam_api_req_new(sata->api, steam_msg, sata);
    steam_api_req_msg(req, msg);

    steam_user_msg_free(msg);
    return 0;
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

    msg = steam_user_msg_new_str(who);
    msg->type = STEAM_USER_MSG_TYPE_TYPING;

    req = steam_api_req_new(sata->api, steam_msg, sata);
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
    SteamUserId *id;
    gchar       *str;

    if (g_ascii_strncasecmp(name, "steamid:", 8) != 0) {
        req = steam_api_req_new(sata->api, steam_user_search, sata);
        steam_api_req_user_search(req, name, 5);
        return;
    }

    str = strchr(name, ':');

    if ((++str)[0] != 0) {
        id  = steam_user_id_new_str(str);
        req = steam_api_req_new(sata->api, steam_user_action, sata);

        steam_api_req_user_add(req, id);
        steam_user_id_free(id);
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
    SteamUserId *id;

    id  = steam_user_id_new_str(name);
    req = steam_api_req_new(sata->api, steam_user_action, sata);;

    steam_api_req_user_remove(req, id);
    steam_user_id_free(id);
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
    SteamUserId *id;

    imcb_buddy_status(ic, who, 0, NULL, NULL);

    id  = steam_user_id_new_str(who);
    req = steam_api_req_new(sata->api, steam_user_action, sata);

    steam_api_req_user_ignore(req, id, TRUE);
    steam_user_id_free(id);
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
    SteamUserId *id;

    id  = steam_user_id_new_str(who);
    req = steam_api_req_new(sata->api, steam_user_action, sata);

    steam_api_req_user_ignore(req, id, FALSE);
    steam_user_id_free(id);
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

    info = steam_user_info_new_str(who);
    req  = steam_api_req_new(sata->api, steam_user_info, sata);

    g_queue_push_head(req->infs, info);
    steam_api_req_user_info(req);
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
    SteamUserId *id;

    id  = steam_user_id_new_str(who);
    req = steam_api_req_new(sata->api, steam_user_action, sata);

    steam_api_req_user_accept(req, id, "accept");
    steam_user_id_free(id);
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
    SteamUserId *id;

    id  = steam_user_id_new_str(who);
    req = steam_api_req_new(sata->api, steam_user_action, sata);

    steam_api_req_user_accept(req, id, "ignore");
    steam_user_id_free(id);
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
    pp->send_typing     = steam_send_typing;
    pp->add_buddy       = steam_add_buddy;
    pp->remove_buddy    = steam_remove_buddy;
    pp->add_permit      = steam_add_permit;
    pp->add_deny        = steam_add_deny;
    pp->rem_permit      = steam_rem_permit;
    pp->rem_deny        = steam_rem_deny;
    pp->get_info        = steam_get_info;
    pp->handle_cmp      = g_ascii_strcasecmp;
    pp->auth_allow      = steam_auth_allow;
    pp->auth_deny       = steam_auth_deny;
    pp->buddy_data_add  = steam_buddy_data_add;
    pp->buddy_data_free = steam_buddy_data_free;

    register_protocol(pp);
}
