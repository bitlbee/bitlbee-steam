/*
 * Copyright 2012-2013 James Geboski <jgeboski@gmail.com>
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
static void steam_summary_u(SteamApi *api, SteamSummary *ss, GError *err,
                            gpointer data);

SteamData *steam_data_new(account_t *acc)
{
    SteamData *sd;
    gchar     *str;

    g_return_val_if_fail(acc != NULL, NULL);

    sd = g_new0(SteamData, 1);

    sd->ic = imcb_new(acc);
    sd->ic->proto_data = sd;

    str = set_getstr(&acc->set, "umqid");
    sd->api = steam_api_new(str);

    sd->api->steamid = g_strdup(set_getstr(&acc->set, "steamid"));
    sd->api->token   = g_strdup(set_getstr(&acc->set, "token"));
    sd->api->sessid  = g_strdup(set_getstr(&acc->set, "sessid"));
    sd->game_status  = set_getbool(&acc->set, "game_status");

    str = set_getstr(&acc->set, "show_playing");
    sd->show_playing = steam_user_mode(str);

    return sd;
}

void steam_data_free(SteamData *sd)
{
    g_return_if_fail(sd != NULL);

    steam_api_free(sd->api);
    g_free(sd);
}

gint steam_user_mode(gchar *mode)
{
    if (mode == NULL)
        return IRC_CHANNEL_USER_NONE;

    switch (mode[0]) {
    case '@': return IRC_CHANNEL_USER_OP;
    case '%': return IRC_CHANNEL_USER_HALFOP;
    case '+': return IRC_CHANNEL_USER_VOICE;

    default:
        return IRC_CHANNEL_USER_NONE;
    }
}

static void steam_buddy_status(SteamData *sd, SteamSummary *ss, bee_user_t *bu)
{
    SteamFriend *frnd;
    const gchar *m;
    gchar       *game;
    gint         f;
    gboolean     cgm;
    gboolean     csv;

    if (ss->state == STEAM_STATE_OFFLINE) {
        imcb_buddy_status(sd->ic, ss->steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_state_str(ss->state);

    if (ss->state != STEAM_STATE_ONLINE)
        f |= OPT_AWAY;

    frnd = bu->data;
    cgm  = g_strcmp0(ss->game,   frnd->game)   != 0;
    csv  = g_strcmp0(ss->server, frnd->server) != 0;

    if (!cgm && !csv) {
        if (frnd->game == NULL)
            imcb_buddy_status(sd->ic, ss->steamid, f, m, bu->status_msg);

        return;
    }

    if (ss->server != NULL)
        game = g_strdup_printf("%s (%s)", ss->game, ss->server);
    else
        game = g_strdup(ss->game);

    if (cgm) {
        imcb_buddy_status(sd->ic, ss->steamid, f, m, game);

        if (ss->game != NULL)
            steam_friend_chans_umode(frnd, sd->show_playing);

        g_free(frnd->game);
        frnd->game = g_strdup(ss->game);
    }

    if (csv) {
        g_free(frnd->server);
        frnd->server = g_strdup(ss->server);
    }

    if (sd->game_status && (game != NULL))
        steam_friend_chans_msg(frnd, "/me is now playing: %s", game);

    g_free(game);
}

static void steam_poll_p(SteamData *sd, SteamMessage *sm)
{
    bee_user_t *bu;
    gchar      *str;
    guint32     f;

    switch (sm->type) {
    case STEAM_MESSAGE_TYPE_EMOTE:
    case STEAM_MESSAGE_TYPE_SAYTEXT:
        bu = imcb_buddy_by_handle(sd->ic, sm->ss->steamid);

        if ((bu != NULL) && (bu->flags & OPT_TYPING))
            imcb_buddy_typing(sd->ic, sm->ss->steamid, 0);

        if (sm->type == STEAM_MESSAGE_TYPE_EMOTE)
            str = g_strconcat("/me ", sm->text, NULL);
        else
            str = g_strdup(sm->text);

        imcb_buddy_msg(sd->ic, sm->ss->steamid, str, 0, sm->tstamp);
        g_free(str);
        return;

    case STEAM_MESSAGE_TYPE_LEFT_CONV:
        imcb_buddy_typing(sd->ic, sm->ss->steamid, 0);
        return;

    case STEAM_MESSAGE_TYPE_RELATIONSHIP:
        goto relationship;

    case STEAM_MESSAGE_TYPE_TYPING:
        bu = imcb_buddy_by_handle(sd->ic, sm->ss->steamid);

        if (G_UNLIKELY(bu == NULL))
            return;

        f = (bu->flags & OPT_TYPING) ? 0 : OPT_TYPING;
        imcb_buddy_typing(sd->ic, sm->ss->steamid, f);
        return;

    default:
        bu = imcb_buddy_by_handle(sd->ic, sm->ss->steamid);

        if (G_UNLIKELY(bu == NULL))
            return;

        steam_buddy_status(sd, sm->ss, bu);
        return;
    }

relationship:
    switch (sm->ss->fstate) {
    case STEAM_FRIEND_STATE_REMOVE:
    case STEAM_FRIEND_STATE_IGNORE:
        imcb_remove_buddy(sd->ic, sm->ss->steamid, NULL);
        return;

    case STEAM_FRIEND_STATE_REQUEST:
        imcb_ask_auth(sd->ic, sm->ss->steamid, sm->ss->nick);
        return;

    case STEAM_FRIEND_STATE_ADD:
        imcb_add_buddy(sd->ic, sm->ss->steamid, NULL);
        imcb_buddy_nick_hint(sd->ic, sm->ss->steamid, sm->ss->nick);
        imcb_rename_buddy(sd->ic, sm->ss->steamid, sm->ss->fullname);

        bu = imcb_buddy_by_handle(sd->ic, sm->ss->steamid);
        steam_buddy_status(sd, sm->ss, bu);
        return;

    default:
        return;
    }
}

static void steam_auth(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;

    acc = sd->ic->acc;

    if (err == NULL) {
        set_setstr(&acc->set, "steamid", api->steamid);
        set_setstr(&acc->set, "token",   api->token);
        set_setstr(&acc->set, "sessid",  api->sessid);
        storage_save(acc->bee->ui_data, NULL, TRUE);

        steam_auth_free(api->auth);
        api->auth = NULL;

        imcb_log(sd->ic, "Authentication finished");
        imcb_log(sd->ic, "Sending login request");
        steam_api_logon(api, steam_logon, sd);
        return;
    }

    set_setstr(&acc->set, "esid", api->auth->esid);
    set_setstr(&acc->set, "cgid", api->auth->cgid);
    imcb_log(sd->ic, "%s", err->message);

    switch (err->code) {
    case STEAM_API_ERROR_AUTH_CAPTCHA:
        imcb_log(sd->ic, "View: %s", api->auth->curl);
        imcb_log(sd->ic, "Run: account %s set captcha <text>", acc->tag);
        break;

    case STEAM_API_ERROR_AUTH_GUARD:
        imcb_log(sd->ic, "Run: account %s set authcode <code>", acc->tag);
        break;
    }

    imc_logout(sd->ic, FALSE);
}

static void steam_friend_action(SteamApi *api, gchar *steamid, GError *err,
                                gpointer data)
{
    SteamData *sd = data;

    if (err != NULL)
        imcb_error(sd->ic, "%s", err->message);
}

static void steam_friend_action_u(SteamApi *api, gchar *steamid, GError *err,
                                  gpointer data)
{
    SteamData *sd = data;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        return;
    }

    steam_api_summary(api, steamid, steam_summary_u, sd);
}

static void steam_friend_search(SteamApi *api, GSList *results, GError *err,
                                gpointer data)
{
    SteamData    *sd = data;
    SteamSummary *ss;
    GSList       *l;
    gchar        *str;
    guint         i;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        return;
    }

    i = g_slist_length(results);

    if (i < 1) {
        imcb_error(sd->ic, "Failed to find any friend(s)");
        return;
    }

    if (i == 1) {
        ss = results->data;
        steam_api_friend_add(api, ss->steamid, steam_friend_action, sd);
        return;
    }

    imcb_log(sd->ic, "Select from one of the following Steam Friends:");

    for (l = results, i = 1; l != NULL; l = l->next, i++) {
        ss  = l->data;
        str = steam_api_profile_url(ss->steamid);

        imcb_log(sd->ic, "%u. `%s' %s", i, ss->nick, str);
        imcb_log(sd->ic, "-- add %s steamid:%s", sd->ic->acc->tag, ss->steamid);
        g_free(str);
    }
}

static void steam_friends(SteamApi *api, GSList *friends, GError *err,
                          gpointer data)
{
    SteamData    *sd = data;
    SteamSummary *ss;
    GSList       *l;
    bee_user_t   *bu;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    imcb_connected(sd->ic);

    for (l = friends; l != NULL; l = l->next) {
        ss = l->data;

        imcb_add_buddy(sd->ic, ss->steamid, NULL);
        imcb_buddy_nick_hint(sd->ic, ss->steamid, ss->nick);
        imcb_rename_buddy(sd->ic, ss->steamid, ss->fullname);

        bu = bee_user_by_handle(sd->ic->bee, sd->ic, ss->steamid);

        if (G_UNLIKELY(bu == NULL))
            continue;

        switch (ss->relation) {
        case STEAM_RELATIONSHIP_FRIEND:
            steam_buddy_status(sd, ss, bu);
            break;

        case STEAM_RELATIONSHIP_IGNORE:
            sd->ic->deny = g_slist_prepend(sd->ic->deny, g_strdup(bu->handle));
            break;
        }
    }

    steam_api_poll(api, steam_poll, sd);
}

static void steam_key(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;
    gchar     *ac;
    gchar     *cc;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, FALSE);
        return;
    }

    acc = sd->ic->acc;
    ac  = set_getstr(&acc->set, "authcode");
    cc  = set_getstr(&acc->set, "captcha");

    imcb_log(sd->ic, "Requesting authentication token");
    steam_api_auth(api, acc->user, acc->pass, ac, cc, steam_auth, sd);
}

static void steam_logoff(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    steam_data_free(sd);
}

static void steam_logon(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    acc = sd->ic->acc;

    set_setstr(&acc->set, "steamid", api->steamid);
    set_setstr(&acc->set, "umqid",   api->umqid);
    storage_save(acc->bee->ui_data, NULL, TRUE);

    imcb_log(sd->ic, "Requesting friends list");
    steam_api_refresh(api);
    steam_api_friends(api, steam_friends, sd);
}

static void steam_relogon(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    if (err == NULL)
        return;

    imcb_error(sd->ic, "%s", err->message);
    imc_logout(sd->ic, TRUE);
}

static void steam_message(SteamApi *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    if (err == NULL)
        return;

    if (err->code == STEAM_API_ERROR_LOGON_EXPIRED) {
        steam_api_relogon(api, steam_relogon, sd);
        return;
    }

    imcb_error(sd->ic, "%s", err->message);
}

static void steam_poll(SteamApi *api, GSList *messages, GError *err,
                       gpointer data)
{
    SteamData *sd = data;
    GSList    *l;

    if (err == NULL) {
        for (l = messages; l != NULL; l = l->next)
            steam_poll_p(sd, l->data);

        steam_api_poll(api, steam_poll, sd);
        return;
    }

    if (err->code == STEAM_API_ERROR_LOGON_EXPIRED) {
        steam_api_relogon(api, steam_relogon, sd);
        return;
    }

    imcb_error(sd->ic, "%s", err->message);
    imc_logout(sd->ic, TRUE);
}

static void steam_summary(SteamApi *api, SteamSummary *ss, GError *err,
                          gpointer data)
{
    SteamData *sd = data;
    gchar     *str;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        return;
    }

    if (ss->nick != NULL)
        imcb_log(sd->ic, "Name:      %s", ss->nick);

    if (ss->game != NULL)
        imcb_log(sd->ic, "Playing:   %s", ss->game);

    if (ss->server != NULL)
        imcb_log(sd->ic, "Server:    steam://connect/%s", ss->server);

    if (ss->fullname != NULL)
        imcb_log(sd->ic, "Real Name: %s", ss->fullname);

    imcb_log(sd->ic, "Steam ID:  %s", ss->steamid);
    imcb_log(sd->ic, "Status:    %s", steam_state_str(ss->state));

    str = steam_api_profile_url(ss->steamid);
    imcb_log(sd->ic, "Profile:   %s", str);
    g_free(str);
}

static void steam_summary_u(SteamApi *api, SteamSummary *ss, GError *err,
                            gpointer data)
{
    SteamData  *sd = data;
    bee_user_t *bu;

    bu = bee_user_by_handle(sd->ic->bee, sd->ic, ss->steamid);

    if (G_LIKELY(bu != NULL))
        steam_buddy_status(sd, ss, bu);
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
    SteamData *sd;

    if (!is_bool(value))
        return SET_INVALID;

    if (acc->ic == NULL)
        return value;

    sd = acc->ic->proto_data;
    sd->game_status = bool2int(value);

    return value;
}

static char *steam_eval_show_playing(set_t *set, char *value)
{
    account_t    *acc = set->data;
    bee_user_t   *bu;
    SteamData    *sd;
    SteamSummary  ss;
    GSList       *l;
    gint          p;

    if ((acc->ic == NULL) || (acc->ic->proto_data == NULL))
        return value;

    sd = acc->ic->proto_data;
    p  = steam_user_mode(value);

    if (p == sd->show_playing)
        return value;

    sd->show_playing = p;

    for (l = acc->bee->users; l; l = l->next) {
        bu = l->data;

        if (!(bu->flags & BEE_USER_ONLINE))
            continue;

        memset(&ss, 0, sizeof ss);

        ss.state    = steam_state_from_str(bu->status);
        ss.steamid  = bu->handle;
        ss.nick     = bu->nick;
        ss.game     = bu->status_msg;
        ss.fullname = bu->fullname;

        steam_buddy_status(sd, &ss, bu);
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
    SteamData *sd;
    gchar     *str;

    sd = steam_data_new(acc);
    imcb_log(sd->ic, "Connecting");

    if ((sd->api->token != NULL) && (sd->api->sessid != NULL)) {
        imcb_log(sd->ic, "Sending logon request");
        steam_api_logon(sd->api, steam_logon, sd);
        return;
    }

    sd->api->auth = steam_auth_new();

    str = set_getstr(&acc->set, "cgid");
    steam_auth_captcha(sd->api->auth, str);

    str = set_getstr(&acc->set, "esid");
    steam_auth_email(sd->api->auth, str);

    imcb_log(sd->ic, "Requesting authentication key");
    steam_api_key(sd->api, acc->user, steam_key, sd);
}

static void steam_logout(struct im_connection *ic)
{
    SteamData *sd = ic->proto_data;

    if (!(ic->flags & OPT_LOGGED_IN)) {
        steam_data_free(sd);
        return;
    }

    steam_http_free_reqs(sd->api->http);
    steam_api_logoff(sd->api, steam_logoff, sd);
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    SteamData    *sd = ic->proto_data;
    SteamMessage *sm;

    sm = steam_message_new(to);
    sm->type = STEAM_MESSAGE_TYPE_SAYTEXT;
    sm->text = g_strdup(message);

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

        sm->type = STEAM_MESSAGE_TYPE_EMOTE;
        sm->text = g_strdup(message + 4);
    } else {
        sm->type = STEAM_MESSAGE_TYPE_SAYTEXT;
        sm->text = g_strdup(message);
    }
    */

    steam_api_message(sd->api, sm, steam_message, sd);
    steam_message_free(sm);
    return 0;
}

static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    SteamData    *sd = ic->proto_data;
    SteamMessage *sm;

    sm = steam_message_new(who);
    sm->type = STEAM_MESSAGE_TYPE_TYPING;

    steam_api_message(sd->api, sm, steam_message, sd);
    steam_message_free(sm);
    return 0;
}

static void steam_add_buddy(struct im_connection *ic, char *name, char * group)
{
    SteamData *sd = ic->proto_data;
    gchar     *str;

    if (g_ascii_strncasecmp(name, "steamid:", 8) != 0) {
        steam_api_friend_search(sd->api, name, 5, steam_friend_search, sd);
        return;
    }

    str = strchr(name, ':');

    if ((++str)[0] != 0)
        steam_api_friend_add(sd->api, str, steam_friend_action, sd);
    else
        imcb_error(sd->ic, "No Steam ID specified");
}

static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char * group)
{
    SteamData *sd = ic->proto_data;

    steam_api_friend_remove(sd->api, name, steam_friend_action, sd);
}

static void steam_add_permit(struct im_connection *ic, char *who)
{

}

static void steam_add_deny(struct im_connection *ic, char *who)
{
    SteamData *sd = ic->proto_data;

    imcb_buddy_status(ic, who, 0, NULL, NULL);
    steam_api_friend_ignore(sd->api, who, TRUE, steam_friend_action, sd);
}

static void steam_rem_permit(struct im_connection *ic, char *who)
{

}

static void steam_rem_deny(struct im_connection *ic, char *who)
{
    SteamData *sd = ic->proto_data;

    steam_api_friend_ignore(sd->api, who, FALSE, steam_friend_action_u, sd);
}

static void steam_get_info(struct im_connection *ic, char *who)
{
    SteamData *sd = ic->proto_data;

    steam_api_summary(sd->api, who, steam_summary, sd);
}

static void steam_auth_allow(struct im_connection *ic, const char *who)
{
    SteamData *sd = ic->proto_data;

    steam_api_friend_accept(sd->api, who, "accept", steam_friend_action, sd);
}

static void steam_auth_deny(struct im_connection *ic, const char *who)
{
    SteamData *sd = ic->proto_data;

    steam_api_friend_accept(sd->api, who, "ignore", steam_friend_action, sd);
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
