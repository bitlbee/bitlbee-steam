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
#include "steam-glib.h"

static void steam_logon(SteamApi *api, GError *err, gpointer data);
static void steam_poll(SteamApi *api, GSList *messages, GError *err,
                       gpointer data);
static void steam_summary_u(SteamApi *api, SteamFriendSummary *smry,
                            GError *err, gpointer data);

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

    sata->api->steamid = g_strdup(set_getstr(&acc->set, "steamid"));
    sata->api->token   = g_strdup(set_getstr(&acc->set, "token"));
    sata->api->sessid  = g_strdup(set_getstr(&acc->set, "sessid"));
    sata->game_status  = set_getbool(&acc->set, "game_status");

    str = set_getstr(&acc->set, "show_playing");
    sata->show_playing = steam_friend_user_mode(str);

    return sata;
}

void steam_data_free(SteamData *sata)
{
    g_return_if_fail(sata != NULL);

    steam_api_free(sata->api);
    g_free(sata);
}

static void steam_buddy_status(SteamData *sata, SteamFriendSummary *smry,
                               bee_user_t *bu)
{
    SteamFriend *frnd;
    const gchar *m;
    gchar       *game;
    gint         f;
    gboolean     cgm;
    gboolean     csv;

    if (smry->state == STEAM_FRIEND_STATE_OFFLINE) {
        imcb_buddy_status(sata->ic, smry->steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_friend_state_str(smry->state);

    if (smry->state != STEAM_FRIEND_STATE_ONLINE)
        f |= OPT_AWAY;

    frnd = bu->data;
    cgm  = g_strcmp0(smry->game,   frnd->game)   != 0;
    csv  = g_strcmp0(smry->server, frnd->server) != 0;

    if (!cgm && !csv) {
        if (frnd->game == NULL)
            imcb_buddy_status(sata->ic, smry->steamid, f, m, bu->status_msg);

        return;
    }

    if (smry->server != NULL)
        game = g_strdup_printf("%s (%s)", smry->game, smry->server);
    else
        game = g_strdup(smry->game);

    if (cgm) {
        imcb_buddy_status(sata->ic, smry->steamid, f, m, game);

        if (smry->game != NULL)
            steam_friend_chans_umode(frnd, sata->show_playing);

        g_free(frnd->game);
        frnd->game = g_strdup(smry->game);
    }

    if (csv) {
        g_free(frnd->server);
        frnd->server = g_strdup(smry->server);
    }

    if (sata->game_status && (game != NULL))
        steam_friend_chans_msg(frnd, "/me is now playing: %s", game);

    g_free(game);
}

static void steam_poll_mesg(SteamData *sata, SteamApiMessage *mesg,
                            gint64 tstamp)
{
    bee_user_t *bu;
    gchar      *str;
    guint32     f;

    switch (mesg->type) {
    case STEAM_API_MESSAGE_TYPE_EMOTE:
    case STEAM_API_MESSAGE_TYPE_SAYTEXT:
        bu = imcb_buddy_by_handle(sata->ic, mesg->smry->steamid);

        if ((bu != NULL) && (bu->flags & OPT_TYPING))
            imcb_buddy_typing(sata->ic, mesg->smry->steamid, 0);

        if (mesg->type == STEAM_API_MESSAGE_TYPE_EMOTE)
            str = g_strconcat("/me ", mesg->text, NULL);
        else
            str = g_strdup(mesg->text);

        imcb_buddy_msg(sata->ic, mesg->smry->steamid, str, 0, tstamp);
        g_free(str);
        return;

    case STEAM_API_MESSAGE_TYPE_LEFT_CONV:
        imcb_buddy_typing(sata->ic, mesg->smry->steamid, 0);
        return;

    case STEAM_API_MESSAGE_TYPE_RELATIONSHIP:
        goto relationship;

    case STEAM_API_MESSAGE_TYPE_TYPING:
        bu = imcb_buddy_by_handle(sata->ic, mesg->smry->steamid);

        if (G_UNLIKELY(bu == NULL))
            return;

        f = (bu->flags & OPT_TYPING) ? 0 : OPT_TYPING;
        imcb_buddy_typing(sata->ic, mesg->smry->steamid, f);
        return;

    default:
        bu = imcb_buddy_by_handle(sata->ic, mesg->smry->steamid);

        if (G_UNLIKELY(bu == NULL))
            return;

        steam_buddy_status(sata, mesg->smry, bu);
        return;
    }

relationship:
    switch (mesg->smry->action) {
    case STEAM_FRIEND_ACTION_REMOVE:
    case STEAM_FRIEND_ACTION_IGNORE:
        imcb_remove_buddy(sata->ic, mesg->smry->steamid, NULL);
        return;

    case STEAM_FRIEND_ACTION_REQUEST:
        imcb_ask_auth(sata->ic, mesg->smry->steamid, mesg->smry->nick);
        return;

    case STEAM_FRIEND_ACTION_ADD:
        imcb_add_buddy(sata->ic, mesg->smry->steamid, NULL);
        imcb_buddy_nick_hint(sata->ic, mesg->smry->steamid, mesg->smry->nick);
        imcb_rename_buddy(sata->ic, mesg->smry->steamid, mesg->smry->fullname);

        bu = imcb_buddy_by_handle(sata->ic, mesg->smry->steamid);
        steam_buddy_status(sata, mesg->smry, bu);
        return;

    default:
        return;
    }
}

static void steam_auth(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sata = data;
    account_t *acc;

    acc = sata->ic->acc;

    if (err == NULL) {
        set_setstr(&acc->set, "steamid", api->steamid);
        set_setstr(&acc->set, "token",   api->token);
        set_setstr(&acc->set, "sessid",  api->sessid);

        steam_auth_free(api->auth);
        api->auth = NULL;

        imcb_log(sata->ic, "Authentication finished");
        imcb_log(sata->ic, "Sending login request");
        steam_api_logon(api, steam_logon, sata);
        return;
    }

    set_setstr(&acc->set, "esid", api->auth->esid);
    set_setstr(&acc->set, "cgid", api->auth->cgid);
    imcb_log(sata->ic, "%s", err->message);

    if (err->domain == STEAM_API_ERROR) {
        switch (err->code) {
        case STEAM_API_ERROR_AUTH_CAPTCHA:
            imcb_log(sata->ic, "View: %s", api->auth->curl);
            imcb_log(sata->ic, "Run: account %s set captcha <text>", acc->tag);
            break;

        case STEAM_API_ERROR_AUTH_GUARD:
            imcb_log(sata->ic, "Run: account %s set authcode <code>", acc->tag);
            break;
        }
    }

    imc_logout(sata->ic, FALSE);
}

static void steam_chatlog(SteamApi *api, GSList *messages, GError *err,
                          gpointer data)
{
    SteamData       *sata = data;
    SteamFriend     *frnd;
    SteamApiMessage *mesg;
    bee_user_t      *bu;
    GSList          *l;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        return;
    }

    for (bu = NULL, l = messages; l != NULL; l = l->next) {
        mesg = l->data;

        if ((bu == NULL) || (g_strcmp0(mesg->smry->steamid, bu->handle) != 0)) {
            bu = bee_user_by_handle(sata->ic->bee, sata->ic,
                                    mesg->smry->steamid);

            if (G_UNLIKELY(bu == NULL))
                continue;

            frnd = bu->data;
        }

        if (mesg->tstamp > frnd->lview)
            steam_poll_mesg(sata, mesg, mesg->tstamp);
    }
}

static void steam_friend_action(SteamApi *api, gchar *steamid, GError *err,
                                gpointer data)
{
    SteamData *sata = data;

    if (err != NULL)
        imcb_error(sata->ic, "%s", err->message);
}

static void steam_friend_action_u(SteamApi *api, gchar *steamid, GError *err,
                                  gpointer data)
{
    SteamData *sata = data;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        return;
    }

    steam_api_summary(api, steamid, steam_summary_u, sata);
}

static void steam_friend_search(SteamApi *api, GSList *results, GError *err,
                                gpointer data)
{
    SteamData          *sata = data;
    SteamFriendSummary *smry;
    GSList             *l;
    const gchar        *tag;
    gchar              *str;
    guint               i;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        return;
    }

    i = g_slist_length(results);

    if (i < 1) {
        imcb_error(sata->ic, "Failed to find any friend(s)");
        return;
    }

    if (i == 1) {
        smry = results->data;
        steam_api_friend_add(api, smry->steamid, steam_friend_action, sata);
        return;
    }

    imcb_log(sata->ic, "Select from one of the following Steam Friends:");
    tag = sata->ic->acc->tag;

    for (l = results, i = 1; l != NULL; l = l->next, i++) {
        smry = l->data;
        str  = steam_api_profile_url(smry->steamid);

        imcb_log(sata->ic, "%u. `%s' %s", i, smry->nick, str);
        imcb_log(sata->ic, "-- add %s steamid:%s", tag, smry->steamid);

        g_free(str);
    }
}

static void steam_friends(SteamApi *api, GSList *friends, GError *err,
                          gpointer data)
{
    SteamData            *sata = data;
    SteamFriendSummary   *smry;
    SteamFriend          *frnd;
    struct im_connection *ic;
    GSList               *l;
    bee_user_t           *bu;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        imc_logout(sata->ic, TRUE);
        return;
    }

    imcb_connected(sata->ic);

    for (l = friends; l != NULL; l = l->next) {
        smry = l->data;

        imcb_add_buddy(sata->ic, smry->steamid, NULL);
        imcb_buddy_nick_hint(sata->ic, smry->steamid, smry->nick);
        imcb_rename_buddy(sata->ic, smry->steamid, smry->fullname);

        bu = bee_user_by_handle(sata->ic->bee, sata->ic, smry->steamid);

        if (G_UNLIKELY(bu == NULL))
            continue;

        frnd = bu->data;
        frnd->lview = smry->lview;

        switch (smry->relation) {
        case STEAM_FRIEND_RELATION_FRIEND:
            steam_buddy_status(sata, smry, bu);
            break;

        case STEAM_FRIEND_RELATION_IGNORE:
            ic = sata->ic;
            ic->deny = g_slist_prepend(ic->deny, g_strdup(bu->handle));
            break;
        }

        if (smry->lmesg > smry->lview)
            steam_api_chatlog(api, smry->steamid, steam_chatlog, sata);
    }

    steam_api_poll(api, steam_poll, sata);
}

static void steam_key(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sata = data;
    account_t *acc;
    gchar     *ac;
    gchar     *cc;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        imc_logout(sata->ic, FALSE);
        return;
    }

    acc = sata->ic->acc;
    ac  = set_getstr(&acc->set, "authcode");
    cc  = set_getstr(&acc->set, "captcha");

    imcb_log(sata->ic, "Requesting authentication token");
    steam_api_auth(api, acc->user, acc->pass, ac, cc, steam_auth, sata);
}

static void steam_logoff(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sata = data;

    steam_data_free(sata);
}

static void steam_logon(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sata = data;
    account_t *acc;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        imc_logout(sata->ic, TRUE);
        return;
    }

    acc = sata->ic->acc;

    set_setstr(&acc->set, "steamid", api->steamid);
    set_setstr(&acc->set, "umqid",   api->umqid);

    imcb_log(sata->ic, "Requesting friends list");
    steam_api_refresh(api);
    steam_api_friends(api, steam_friends, sata);
}

static void steam_message(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sata = data;

    if (err != NULL)
        imcb_error(sata->ic, "%s", err->message);
}

static void steam_poll(SteamApi *api, GSList *messages, GError *err,
                       gpointer data)
{
    SteamData *sata = data;
    GSList    *l;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        imc_logout(sata->ic, TRUE);
        return;
    }

    for (l = messages; l != NULL; l = l->next)
        steam_poll_mesg(sata, l->data, 0);

    steam_api_poll(api, steam_poll, sata);
}

static void steam_summary(SteamApi *api, SteamFriendSummary *smry,
                          GError *err, gpointer data)
{
    SteamData *sata = data;
    gchar     *str;
    gint64     in;

    if (err != NULL) {
        imcb_error(sata->ic, "%s", err->message);
        return;
    }

    if (smry->nick != NULL)
        imcb_log(sata->ic, "Name:       %s", smry->nick);

    if (smry->game != NULL)
        imcb_log(sata->ic, "Playing:    %s", smry->game);

    if (smry->server != NULL)
        imcb_log(sata->ic, "Server:     steam://connect/%s", smry->server);

    if (smry->fullname != NULL)
        imcb_log(sata->ic, "Real Name:  %s", smry->fullname);

    in = steam_api_accountid_str(smry->steamid);
    imcb_log(sata->ic, "Account ID: %" G_GINT64_FORMAT, in);

    imcb_log(sata->ic, "Steam ID:   %s", smry->steamid);

    str = (gchar *) steam_friend_state_str(smry->state);
    imcb_log(sata->ic, "Status:     %s", str);

    str = steam_api_profile_url(smry->steamid);
    imcb_log(sata->ic, "Profile:    %s", str);
    g_free(str);
}

static void steam_summary_u(SteamApi *api, SteamFriendSummary *smry,
                            GError *err, gpointer data)
{
    SteamData  *sata = data;
    bee_user_t *bu;

    bu = bee_user_by_handle(sata->ic->bee, sata->ic, smry->steamid);

    if (G_LIKELY(bu != NULL))
        steam_buddy_status(sata, smry, bu);
}

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

static char *steam_eval_show_playing(set_t *set, char *value)
{
    account_t   *acc = set->data;
    SteamData   *sata;
    SteamFriend *frnd;
    bee_user_t  *bu;
    GSList      *l;
    gint         sply;

    if ((acc->ic == NULL) || (acc->ic->proto_data == NULL))
        return value;

    sata = acc->ic->proto_data;
    sply = steam_friend_user_mode(value);

    if (sply == sata->show_playing)
        return value;

    sata->show_playing = sply;

    for (l = acc->bee->users; l; l = l->next) {
        bu   = l->data;
        frnd = bu->data;

        if (!(bu->flags & BEE_USER_ONLINE) || (frnd->game == NULL))
            continue;

        imcb_buddy_status(acc->ic, bu->handle, bu->flags,
                          bu->status, bu->status_msg);
        steam_friend_chans_umode(frnd, sata->show_playing);
    }

    return value;
}

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

    s = set_add(&acc->set, "steamid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

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

static void steam_login(account_t *acc)
{
    SteamData *sata;
    gchar     *str;

    sata = steam_data_new(acc);
    imcb_log(sata->ic, "Connecting");

    if ((sata->api->token != NULL) && (sata->api->sessid != NULL)) {
        imcb_log(sata->ic, "Sending logon request");
        steam_api_logon(sata->api, steam_logon, sata);
        return;
    }

    sata->api->auth = steam_auth_new();

    str = set_getstr(&acc->set, "cgid");
    steam_auth_captcha(sata->api->auth, str);

    str = set_getstr(&acc->set, "esid");
    steam_auth_email(sata->api->auth, str);

    imcb_log(sata->ic, "Requesting authentication key");
    steam_api_key(sata->api, acc->user, steam_key, sata);
}

static void steam_logout(struct im_connection *ic)
{
    SteamData *sata = ic->proto_data;

    steam_http_free_reqs(sata->api->http);

    if (ic->flags & OPT_LOGGED_IN)
        steam_api_logoff(sata->api, steam_logoff, sata);
    else
        steam_data_free(sata);
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    SteamData       *sata = ic->proto_data;
    SteamApiMessage *mesg;

    mesg = steam_api_message_new(to);
    mesg->type = STEAM_API_MESSAGE_TYPE_SAYTEXT;
    mesg->text = g_strdup(message);

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

        mesg->type = STEAM_API_MESSAGE_TYPE_EMOTE;
        mesg->text = g_strdup(message + 4);
    } else {
        mesg->type = STEAM_API_MESSAGE_TYPE_SAYTEXT;
        mesg->text = g_strdup(message);
    }
    */

    steam_api_message(sata->api, mesg, steam_message, sata);
    steam_api_message_free(mesg);
    return 0;
}

static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    SteamData       *sata = ic->proto_data;
    SteamApiMessage *mesg;

    mesg = steam_api_message_new(who);
    mesg->type = STEAM_API_MESSAGE_TYPE_TYPING;

    steam_api_message(sata->api, mesg, steam_message, sata);
    steam_api_message_free(mesg);
    return 0;
}

static void steam_add_buddy(struct im_connection *ic, char *name, char * group)
{
    SteamData *sata = ic->proto_data;
    gchar     *str;

    if (g_ascii_strncasecmp(name, "steamid:", 8) != 0) {
        steam_api_friend_search(sata->api, name, 5, steam_friend_search, sata);
        return;
    }

    str = strchr(name, ':');

    if ((++str)[0] != 0)
        steam_api_friend_add(sata->api, str, steam_friend_action, sata);
    else
        imcb_error(sata->ic, "No Steam ID specified");
}

static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char * group)
{
    SteamData *sata = ic->proto_data;

    steam_api_friend_remove(sata->api, name, steam_friend_action, sata);
}

static void steam_add_permit(struct im_connection *ic, char *who)
{

}

static void steam_add_deny(struct im_connection *ic, char *who)
{
    SteamData *sata = ic->proto_data;

    imcb_buddy_status(ic, who, 0, NULL, NULL);
    steam_api_friend_ignore(sata->api, who, TRUE, steam_friend_action, sata);
}

static void steam_rem_permit(struct im_connection *ic, char *who)
{

}

static void steam_rem_deny(struct im_connection *ic, char *who)
{
    SteamData *sata = ic->proto_data;

    steam_api_friend_ignore(sata->api, who, FALSE, steam_friend_action_u,
                            sata);
}

static void steam_get_info(struct im_connection *ic, char *who)
{
    SteamData *sata = ic->proto_data;

    steam_api_summary(sata->api, who, steam_summary, sata);
}

static void steam_auth_allow(struct im_connection *ic, const char *who)
{
    SteamData *sata = ic->proto_data;

    steam_api_friend_accept(sata->api, who, "accept", steam_friend_action,
                            sata);
}

static void steam_auth_deny(struct im_connection *ic, const char *who)
{
    SteamData *sata = ic->proto_data;

    steam_api_friend_accept(sata->api, who, "ignore", steam_friend_action,
                            sata);
}

static void steam_buddy_data_add(struct bee_user *bu)
{
    bu->data = steam_friend_new(bu);
}

static void steam_buddy_data_free(struct bee_user *bu)
{
    steam_friend_free(bu->data);
}

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
