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

#include "steam.h"
#include "steam-util.h"

static void steam_logon_cb(SteamAPI *api, SteamError err, gpointer data);

static void steam_poll_cb(SteamAPI *api, GSList *m_updates, SteamError err,
                          gpointer data);

static void steam_summaries_cb(SteamAPI *api, GSList *m_updates,
                               SteamError err, gpointer data);


static gboolean steam_main_loop(gpointer data, gint fd, b_input_condition cond)
{
    SteamData *sd = data;

    g_return_val_if_fail(sd != NULL, FALSE);

    sd->ml_id = 0;

    if (sd->poll)
        steam_api_poll(sd->api, steam_poll_cb, sd);

    return FALSE;
}

static void steam_auth_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;
    gchar     *msg;

    guint i;

    g_return_if_fail(sd != NULL);

    switch (err) {
    case STEAM_ERROR_SUCCESS:
        set_setstr(&sd->ic->acc->set, "token", api->token);

        imcb_log(sd->ic, "Authentication finished");
        imcb_log(sd->ic, "Sending login request");
        steam_api_logon(api, steam_logon_cb, sd);
        break;

    case STEAM_ERROR_INVALID_AUTH_CODE:
        imcb_error(sd->ic, "SteamGuard authentication code invalid");
        imc_logout(sd->ic, FALSE);
        break;

    case STEAM_ERROR_REQ_AUTH_CODE:
        acc = sd->ic->acc->bee->accounts;

        for (i = 0; acc != NULL; acc = acc->next, i++) {
            if (sd->ic->acc == acc)
                break;
        }

        imcb_log(sd->ic, "SteamGuard requires an authentication code");
        imcb_log(sd->ic, "An authentication code has been emailed to you");
        imcb_log(sd->ic, "Run: account %d set authcode <code>", i);
        imc_logout(sd->ic, FALSE);
        break;

    default:
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, FALSE);
    }
}

static void steam_friends_cb(SteamAPI *api, GSList *friends, SteamError err,
                             gpointer data)
{
    SteamData *sd = data;
    GSList    *fl;

    g_return_if_fail(sd != NULL);

    if (err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));

        if (err != STEAM_ERROR_EMPTY_FRIENDS) {
            imc_logout(sd->ic, TRUE);
            return;
        }
    }

    for (fl = friends; fl != NULL; fl = fl->next)
        imcb_add_buddy(sd->ic, fl->data, NULL);

    steam_api_summaries(sd->api, friends, steam_summaries_cb, sd);
}

static void steam_logon_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if (err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    imcb_log(sd->ic, "Requesting friends list");
    steam_api_friends(sd->api, steam_friends_cb, sd);
}

static void steam_reset_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    imcb_log(sd->ic, "Sending logon request");
    steam_api_logon(sd->api, steam_logon_cb, sd);
}

static void steam_logoff_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    steam_data_free(sd);
}

static void steam_message_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if (err == STEAM_ERROR_SUCCESS)
        return;

    imcb_error(sd->ic, steam_api_error_str(err));
    imc_logout(sd->ic, TRUE);
}

static void steam_poll_cb(SteamAPI *api, GSList *m_updates, SteamError err,
                          gpointer data)
{
    SteamData    *sd = data;
    SteamMessage *sm;
    bee_user_t   *bu;

    GSList *l;
    gchar  *m;
    gint    f;

    g_return_if_fail(sd != NULL);

    if (!sd->poll)
        return;

    if (err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    for (l = m_updates; l != NULL; l = l->next) {
        sm = l->data;
        bu = imcb_buddy_by_handle(sd->ic, sm->steamid);

        if (bu == NULL)
            continue;

        switch (sm->type) {
        case STEAM_MESSAGE_TYPE_EMOTE:
        case STEAM_MESSAGE_TYPE_SAYTEXT:
            if (sm->type == STEAM_MESSAGE_TYPE_EMOTE)
                m = g_strconcat("/me ", sm->text, NULL);
            else
                m = g_strdup(sm->text);

            imcb_buddy_msg(sd->ic, sm->steamid, m, 0, 0);
            imcb_buddy_typing(sd->ic, sm->steamid, 0);

            g_free(m);
            break;

        case STEAM_MESSAGE_TYPE_LEFT_CONV:
            imcb_buddy_typing(sd->ic, sm->steamid, 0);
            break;

        case STEAM_MESSAGE_TYPE_STATE:
            if (sd->show_playing == STEAM_CHANNEL_USER_OFF) {
                steam_util_buddy_status(sd, sm->steamid, sm->state, NULL);
                break;
            }

            if (sm->state == STEAM_STATE_OFFLINE)
                steam_util_buddy_status(sd, sm->steamid, sm->state, NULL);
            else
                steam_api_summary(sd->api, sm->steamid, steam_summaries_cb, sd);
            break;

        case STEAM_MESSAGE_TYPE_TYPING:
            if (bu->flags & OPT_TYPING)
                imcb_buddy_typing(sd->ic, sm->steamid, 0);
            else
                imcb_buddy_typing(sd->ic, sm->steamid, OPT_TYPING);
            break;
        }
    }

    sd->ml_id = b_timeout_add(1000, steam_main_loop, sd);
}

static void steam_summaries_cb(SteamAPI *api, GSList *m_updates,
                               SteamError err, gpointer data)
{
    SteamData    *sd = data;
    SteamSummary *ss;
    bee_user_t   *bu;
    GSList       *l;

    g_return_if_fail(sd != NULL);

    if (err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    if (!(sd->ic->flags & OPT_LOGGED_IN))
        imcb_connected(sd->ic);

    for (l = m_updates; l != NULL; l = l->next) {
        ss = l->data;

        if (!sd->poll)
            imcb_buddy_nick_hint(sd->ic, ss->steamid, ss->name);

        steam_util_buddy_status(sd, ss->steamid, ss->state, ss->game);
    }

    if (sd->poll)
        return;

    sd->poll = TRUE;
    steam_api_poll(sd->api, steam_poll_cb, sd);
}

static void steam_summary_cb(SteamAPI *api, GSList *summaries,
                             SteamError err, gpointer data)
{
    SteamData    *sd = data;
    SteamSummary *ss;
    gchar        *url;

    g_return_if_fail(sd != NULL);

    if (err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    ss = summaries->data;

    if (ss->name != NULL)
        imcb_log(sd->ic, "Name:      %s", ss->name);

    if (ss->game != NULL)
        imcb_log(sd->ic, "Playing:   %s", ss->game);

    if (ss->server != NULL) {
        url = (sd->server_url) ? "steam://connect/" : "";
        imcb_log(sd->ic, "Server:    %s%s", url, ss->server);
    }

    if (ss->realname != NULL)
        imcb_log(sd->ic, "Real Name: %s", ss->realname);

    imcb_log(sd->ic, "Steam ID:  %s", ss->steamid);
    imcb_log(sd->ic, "Status:    %s", steam_state_str(ss->state));

    if (ss->profile != NULL)
        imcb_log(sd->ic, "Profile:   %s", ss->profile);
}

static char *steam_eval_authcode(set_t *set, char *value)
{
    account_t *acc = set->data;

    g_return_val_if_fail(acc != NULL, value);

    if ((acc->ic != NULL) && (acc->ic->flags & OPT_LOGGED_IN))
        return NULL;

    /* Some hackery to auto connect upon authcode entry */

    g_free(set->value);
    set->value = g_strdup(value);

    account_on(acc->bee, acc);

    g_free(set->value);
    set->value = NULL;

    return NULL;
}

static char *steam_eval_show_playing(set_t *set, char *value)
{
    account_t  *acc = set->data;
    bee_user_t *bu;
    GSList     *l;
    gint        p;

    SteamData  *sd;
    SteamState  s;

    g_return_val_if_fail(acc      != NULL, value);
    g_return_val_if_fail(acc->bee != NULL, value);

    if (acc->ic == NULL)
        return value;

    sd = acc->ic->proto_data;

    if (sd == NULL)
        return value;

    p = steam_util_user_mode(value);

    if (p == sd->show_playing)
        return value;

    sd->show_playing = p;

    for (l = acc->bee->users; l; l = l->next) {
        bu = l->data;

        if (!(bu->flags & BEE_USER_ONLINE))
            continue;

        s = steam_state_from_str(bu->status);
        steam_util_buddy_status(sd, bu->handle, s, bu->status_msg);
    }

    return value;
}

static char *steam_eval_server_url(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sd;

    g_return_val_if_fail(acc != NULL, value);

    if (!is_bool(value))
        return SET_INVALID;

    if (acc->ic == NULL)
        return value;

    sd = acc->ic->proto_data;
    sd->server_url = bool2int(value);

    return value;
}

static void steam_init(account_t *acc)
{
    set_t *s;

    s = set_add(&acc->set, "authcode", NULL, steam_eval_authcode, acc);
    s->flags = SET_NOSAVE | SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "token", NULL, NULL, acc);
    s->flags = SET_HIDDEN;

    s = set_add(&acc->set, "umqid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "show_playing", "%", steam_eval_show_playing, acc);
    s->flags = SET_NULL_OK;

    set_add(&acc->set, "server_url", "true", steam_eval_server_url, acc);
}

static void steam_login(account_t *acc)
{
    SteamData *sd;
    gchar     *tmp;

    tmp = set_getstr(&acc->set, "umqid");
    sd  = steam_data_new(acc, tmp);

    set_setstr(&acc->set, "umqid", sd->api->umqid);
    tmp = set_getstr(&acc->set, "show_playing");

    sd->api->token   = g_strdup(set_getstr(&acc->set, "token"));
    sd->show_playing = steam_util_user_mode(tmp);
    sd->server_url   = set_getbool(&acc->set, "server_url");

    imcb_log(sd->ic, "Connecting");

    if (sd->api->token != NULL) {
        imcb_log(sd->ic, "Resetting UMQID");
        steam_api_logoff(sd->api, steam_reset_cb, sd);
        return;
    }

    tmp = set_getstr(&acc->set, "authcode");

    imcb_log(sd->ic, "Requesting token");
    steam_api_auth(sd->api, tmp, acc->user, acc->pass, steam_auth_cb, sd);
}

static void steam_logout(struct im_connection *ic)
{
    SteamData *sd = ic->proto_data;

    g_return_if_fail(sd != NULL);

    sd->poll = FALSE;

    if (sd->ml_id > 0)
        b_event_remove(sd->ml_id);

    if (ic->flags & OPT_LOGGING_OUT) {
        steam_http_free_reqs(sd->api->http);
        steam_api_logoff(sd->api, steam_logoff_cb, sd);
    } else {
        steam_data_free(sd);
    }
}

static GList *steam_away_states(struct im_connection *ic)
{
    GList *l = NULL;

    l = g_list_append(l, steam_state_str(STEAM_STATE_AWAY));
    l = g_list_append(l, steam_state_str(STEAM_STATE_BUSY));
    l = g_list_append(l, steam_state_str(STEAM_STATE_SNOOZE));

    return l;
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    SteamData    *sd = ic->proto_data;
    SteamMessage  sm;

    g_return_val_if_fail(sd != NULL, 0);

    memset(&sm, 0, sizeof sm);
    sm.steamid = to;

    if (g_str_has_prefix(message, "/me")) {
        if (strlen(message) < 5)
            return 0;

        sm.type = STEAM_MESSAGE_TYPE_EMOTE;
        sm.text = message + 4;
    } else {
        sm.type = STEAM_MESSAGE_TYPE_SAYTEXT;
        sm.text = message;
    }

    steam_api_message(sd->api, &sm, steam_message_cb, sd);
    return 0;
}

static void steam_set_away(struct im_connection *ic, char *state,
                           char *message)
{
    /* Set away status if possible via API */
}

static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    SteamData    *sd = ic->proto_data;
    SteamMessage  sm;

    g_return_val_if_fail(sd != NULL, 0);

    memset(&sm, 0, sizeof sm);
    sm.type    = STEAM_MESSAGE_TYPE_TYPING;
    sm.steamid = who;

    steam_api_message(sd->api, &sm, steam_message_cb, sd);
    return 0;
}

static void steam_add_buddy(struct im_connection *ic, char *name, char * group)
{
    /* Add/search for a buddy if possible via API */
}

static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char * group)
{
    /* It looks like this can be done via the Steam Community AJAX API */
}

static void steam_get_info(struct im_connection *ic, char *who)
{
    SteamData *sd = ic->proto_data;

    g_return_if_fail(sd != NULL);

    steam_api_summary(sd->api, who, steam_summary_cb, sd);
}

void init_plugin()
{
    struct prpl *pp;

    pp = g_new0(struct prpl, 1);

    pp->name         = "steam";
    pp->mms          = 0;
    pp->init         = steam_init;
    pp->login        = steam_login;
    pp->logout       = steam_logout;
    pp->away_states  = steam_away_states;
    pp->buddy_msg    = steam_buddy_msg;
    pp->set_away     = steam_set_away;
    pp->send_typing  = steam_send_typing;
    pp->add_buddy    = steam_add_buddy;
    pp->remove_buddy = steam_remove_buddy;
    pp->get_info     = steam_get_info;
    pp->handle_cmp   = g_strcmp0;

    register_protocol(pp);
}

SteamData *steam_data_new(account_t *acc, const gchar *umqid)
{
    SteamData *sd;

    g_return_val_if_fail(acc != NULL, NULL);

    sd = g_new0(SteamData, 1);

    sd->ic   = imcb_new(acc);
    sd->api  = steam_api_new(umqid);
    sd->poll = FALSE;

    acc->ic            = sd->ic;
    sd->ic->proto_data = sd;

    return sd;
}

void steam_data_free(SteamData *sd)
{
    g_return_if_fail(sd != NULL);

    steam_api_free(sd->api);
    g_free(sd);
}
