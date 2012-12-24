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

static void steam_logon_cb(SteamAPI *api, GError *err, gpointer data);

static void steam_poll_cb(SteamAPI *api, GSList *m_updates, GError *err,
                          gpointer data);

static void steam_summaries_cb(SteamAPI *api, GSList *m_updates,
                               GError *err, gpointer data);


static gboolean steam_main_loop(gpointer data, gint fd, b_input_condition cond)
{
    SteamData *sd = data;

    g_return_val_if_fail(sd != NULL, FALSE);

    sd->ml_id = 0;

    if (sd->poll)
        steam_api_poll(sd->api, steam_poll_cb, sd);

    return FALSE;
}

static void steam_buddy_status(SteamData *sd, SteamSummary *ss, bee_user_t *bu)
{
    irc_channel_t      *ic;
    irc_user_t         *iu;
    irc_channel_user_t *icu;
    SteamState          st;

    GSList *l;
    gchar  *m;
    gint    f;

    g_return_if_fail(sd != NULL);
    g_return_if_fail(ss != NULL);

    if (bu == NULL) {
        bu = bee_user_by_handle(sd->ic->bee, sd->ic, ss->steamid);

        if (bu == NULL)
            return;
    }

    /* Check rather than freeing/reallocating */
    if (g_strcmp0(bu->nick, ss->nick))
        imcb_buddy_nick_hint(sd->ic, ss->steamid, ss->nick);

    imcb_rename_buddy(sd->ic, ss->steamid, ss->fullname);

    if (bu->data != NULL) {
        memcpy(&st, bu->data, sizeof st);
        g_free(bu->data);
        bu->data = NULL;

        switch (st) {
        case STEAM_STATE_REQUEST:
            imcb_log(sd->ic, "Friendship invite from `%s'", ss->nick);
            return;

        case STEAM_STATE_REQUESTED:
            imcb_log(sd->ic, "Friendship invitation sent to `%s'", ss->nick);
            return;

        default:
            break;
        }
    }

    if (ss->state == STEAM_STATE_OFFLINE) {
        imcb_buddy_status(sd->ic, ss->steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_state_str(ss->state);

    if (ss->state != STEAM_STATE_ONLINE)
        f |= OPT_AWAY;

    imcb_buddy_status(sd->ic, ss->steamid, f, m, ss->game);

    if (!sd->extra_info || (ss->game == NULL))
        return;

    iu = bu->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic  = l->data;
        icu = irc_channel_has_user(ic, iu);
        f   = sd->show_playing;

        if (icu != NULL)
            f |= icu->flags;

        irc_channel_user_set_mode(ic, iu, f);
    }
}

static void steam_poll_cb_p(SteamData *sd, SteamMessage *sm)
{
    bee_user_t   *bu;
    gchar        *m;
    SteamSummary  ss;

    bu = imcb_buddy_by_handle(sd->ic, sm->steamid);

    if (bu == NULL) {
        if (sm->type != STEAM_MESSAGE_TYPE_RELATIONSHIP)
            return;

        switch (sm->state) {
        case STEAM_STATE_REQUEST:
        case STEAM_STATE_REQUESTED:
            imcb_add_buddy(sd->ic, sm->steamid, NULL);
            bu = imcb_buddy_by_handle(sd->ic, sm->steamid);
            break;

        default:
            return;
        }

        if (G_UNLIKELY(bu == NULL))
            return;
    }

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

    case STEAM_MESSAGE_TYPE_RELATIONSHIP:
        switch (sm->state) {
        case STEAM_STATE_REMOVE:
            imcb_log(sd->ic, "Removed `%s' from friends list", bu->nick);
            imcb_remove_buddy(sd->ic, sm->steamid, NULL);
            break;

        case STEAM_STATE_IGNORE:
            imcb_log(sd->ic, "Friendship invite from `%s' ignored", bu->nick);
            imcb_remove_buddy(sd->ic, sm->steamid, NULL);
            return;

        case STEAM_STATE_ADD:
            imcb_log(sd->ic, "Added `%s' to friends list", bu->nick);
            steam_api_summary(sd->api, sm->steamid, steam_summaries_cb, sd);
            break;

        case STEAM_STATE_REQUEST:
        case STEAM_STATE_REQUESTED:
            g_free(bu->data);
            bu->data = g_memdup(&sm->state, sizeof sm->state);
            steam_api_summary(sd->api, sm->steamid, steam_summaries_cb, sd);
            break;

        default:
            break;
        }
        break;

    case STEAM_MESSAGE_TYPE_STATE:
        if (sd->extra_info) {
            steam_api_summary(sd->api, sm->steamid, steam_summaries_cb, sd);
            break;
        }

        steam_util_smtoss(sm, &ss);
        steam_buddy_status(sd, &ss, bu);
        break;

    case STEAM_MESSAGE_TYPE_TYPING:
        if (bu->flags & OPT_TYPING)
            imcb_buddy_typing(sd->ic, sm->steamid, 0);
        else
            imcb_buddy_typing(sd->ic, sm->steamid, OPT_TYPING);
        break;

    default:
        break;
    }
}

static void steam_auth_cb(SteamAPI *api, GError *err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;
    irc_t     *irc;

    guint i;

    g_return_if_fail(sd != NULL);

    if (err == NULL) {
        acc = sd->ic->acc;
        irc = acc->bee->ui_data;

        set_setstr(&acc->set, "token", api->token);
        storage_save(irc, NULL, TRUE);

        imcb_log(sd->ic, "Authentication finished");
        imcb_log(sd->ic, "Sending login request");
        steam_api_logon(api, steam_logon_cb, sd);
        return;
    }

    imcb_log(sd->ic, "%s", err->message);

    if (err->code == STEAM_API_ERROR_AUTH_REQ) {
        acc = sd->ic->acc->bee->accounts;

        for (i = 0; acc != NULL; acc = acc->next, i++) {
            if (sd->ic->acc == acc)
                break;
        }

        imcb_log(sd->ic, "Run: account %d set authcode <code>", i);
    }

    imc_logout(sd->ic, FALSE);
}

static void steam_friends_cb(SteamAPI *api, GSList *friends, GError *err,
                             gpointer data)
{
    SteamData *sd = data;
    GSList    *fl;

    g_return_if_fail(sd != NULL);

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);

        if (err->code != STEAM_API_ERROR_FRIENDS) {
            imc_logout(sd->ic, TRUE);
            return;
        }
    }

    for (fl = friends; fl != NULL; fl = fl->next)
        imcb_add_buddy(sd->ic, fl->data, NULL);

    steam_api_summaries(sd->api, friends, steam_summaries_cb, sd);
}

static void steam_logon_cb(SteamAPI *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    imcb_log(sd->ic, "Requesting friends list");
    steam_api_friends(sd->api, steam_friends_cb, sd);
}

static void steam_reset_cb(SteamAPI *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    imcb_log(sd->ic, "Sending logon request");
    steam_api_logon(sd->api, steam_logon_cb, sd);
}

static void steam_logoff_cb(SteamAPI *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    steam_data_free(sd);
}

static void steam_message_cb(SteamAPI *api, GError *err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if (err == NULL)
        return;

    imcb_error(sd->ic, "%s", err->message);
    imc_logout(sd->ic, TRUE);
}

static void steam_poll_cb(SteamAPI *api, GSList *m_updates, GError *err,
                          gpointer data)
{
    SteamData *sd = data;
    GSList    *l;

    g_return_if_fail(sd != NULL);

    if (!sd->poll)
        return;

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    for (l = m_updates; l != NULL; l = l->next)
        steam_poll_cb_p(sd, l->data);

    sd->ml_id = b_timeout_add(1000, steam_main_loop, sd);
}

static void steam_summaries_cb(SteamAPI *api, GSList *m_updates, GError *err,
                               gpointer data)
{
    SteamData *sd = data;
    GSList    *l;

    g_return_if_fail(sd != NULL);

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    if (!(sd->ic->flags & OPT_LOGGED_IN))
        imcb_connected(sd->ic);

    for (l = m_updates; l != NULL; l = l->next)
        steam_buddy_status(sd, l->data, NULL);

    if (sd->poll)
        return;

    sd->poll = TRUE;
    steam_api_poll(sd->api, steam_poll_cb, sd);
}

static void steam_summary_cb(SteamAPI *api, GSList *summaries, GError *err,
                             gpointer data)
{
    SteamData    *sd = data;
    SteamSummary *ss;
    gchar        *url;

    g_return_if_fail(sd != NULL);

    if (err != NULL) {
        imcb_error(sd->ic, "%s", err->message);
        imc_logout(sd->ic, TRUE);
        return;
    }

    ss = summaries->data;

    if (ss->nick != NULL)
        imcb_log(sd->ic, "Name:      %s", ss->nick);

    if (ss->game != NULL)
        imcb_log(sd->ic, "Playing:   %s", ss->game);

    if (ss->server != NULL) {
        url = (sd->server_url) ? "steam://connect/" : "";
        imcb_log(sd->ic, "Server:    %s%s", url, ss->server);
    }

    if (ss->fullname != NULL)
        imcb_log(sd->ic, "Real Name: %s", ss->fullname);

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

    SteamData    *sd;
    SteamSummary  ss;

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

static char *steam_eval_extra_info(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sd;

    g_return_val_if_fail(acc != NULL, value);

    if (!is_bool(value))
        return SET_INVALID;

    if (acc->ic == NULL)
        return value;

    sd = acc->ic->proto_data;
    sd->extra_info = bool2int(value);

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

    set_add(&acc->set, "extra_info", "true", steam_eval_extra_info, acc);
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
    sd->extra_info   = set_getbool(&acc->set, "extra_info");
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

static void steam_buddy_data_free(struct bee_user *bu)
{
    g_free(bu->data);
}

void init_plugin()
{
    struct prpl *pp;

    pp = g_new0(struct prpl, 1);

    pp->name            = "steam";
    pp->mms             = 0;
    pp->init            = steam_init;
    pp->login           = steam_login;
    pp->logout          = steam_logout;
    pp->away_states     = steam_away_states;
    pp->buddy_msg       = steam_buddy_msg;
    pp->set_away        = steam_set_away;
    pp->send_typing     = steam_send_typing;
    pp->add_buddy       = steam_add_buddy;
    pp->remove_buddy    = steam_remove_buddy;
    pp->get_info        = steam_get_info;
    pp->handle_cmp      = g_strcmp0;
    pp->buddy_data_free = steam_buddy_data_free;

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
