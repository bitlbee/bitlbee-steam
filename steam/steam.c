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

#include "steam.h"

static void steam_logon_cb(SteamAPI *api, SteamError err, gpointer data);

static void steam_poll_cb(SteamAPI *api, GSList *m_updates, SteamError err,
                          gpointer data);

static gboolean steam_main_loop(gpointer data, gint fd, b_input_condition cond)
{
    SteamData *sd = data;

    g_return_val_if_fail(sd != NULL, FALSE);

    sd->ml_id = 0;

    if(sd->ic == NULL)
        return FALSE;

    if((sd->ic->flags & OPT_LOGGED_IN) && !(sd->ic->flags & OPT_LOGGING_OUT))
        steam_api_poll(sd->api, steam_poll_cb, sd);

    return FALSE;
}

static void steam_auth_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;
    account_t *acc;
    gchar *msg;
    guint i;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    switch(err) {
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

        for(i = 0; acc != NULL; acc = acc->next, i++) {
            if(sd->ic->acc == acc)
                break;
        }

        imcb_log(sd->ic, "SteamGuard requires an authentication code");
        imcb_log(sd->ic, "An authentication code has been emailed to you");
        imcb_log(sd->ic, "Run: account %d set authcode <code>", i);
        break;

    default:
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, FALSE);
    }
}

static void steam_logon_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

   if(err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    imcb_log(sd->ic, "Requesting friends list");
    steam_api_poll(sd->api, steam_poll_cb, sd);
    imcb_connected(sd->ic);
}

static void steam_reset_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    imcb_log(sd->ic, "Sending logon request");
    steam_api_logon(sd->api, steam_logon_cb, sd);
}

static void steam_renew_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    if(err == STEAM_ERROR_SUCCESS) {
        steam_api_poll(sd->api, steam_poll_cb, sd);
        return;
    }

    imcb_error(sd->ic, steam_api_error_str(err));
    imc_logout(sd->ic, TRUE);
}

static void steam_logoff_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    steam_data_free(sd);
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
    guint   ts;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    if(err == STEAM_ERROR_NOT_AUTHORIZED) {
        steam_api_logon(api, steam_renew_cb, sd);
        return;
    }

    if(err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        imc_logout(sd->ic, TRUE);
        return;
    }

    for(l = m_updates; l != NULL; l = l->next) {
        sm  = l->data;
        ts |= sm->type;

        switch(sm->type) {
        case STEAM_MESSAGE_TYPE_EMOTE:
        case STEAM_MESSAGE_TYPE_SAYTEXT:
            if(sm->type == STEAM_MESSAGE_TYPE_EMOTE)
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
            if(sm->state == STEAM_STATE_OFFLINE) {
                if(imcb_buddy_by_handle(sd->ic, sm->steamid) != NULL)
                    imcb_buddy_status(sd->ic, sm->steamid, OPT_LOGGING_OUT,
                                      NULL, NULL);

                imcb_remove_buddy(sd->ic, sm->steamid, NULL);
                break;
            }

            m = steam_state_str(sm->state);
            f = OPT_LOGGED_IN;

            if(sm->state != STEAM_STATE_ONLINE)
                f |= OPT_AWAY;

            imcb_add_buddy(sd->ic, sm->steamid, NULL);
            imcb_buddy_nick_hint(sd->ic, sm->steamid, sm->name);
            imcb_buddy_status(sd->ic, sm->steamid, f, m, NULL);
            break;

        case STEAM_MESSAGE_TYPE_TYPING:
            bu = imcb_buddy_by_handle(sd->ic, sm->steamid);

            if(bu == NULL)
                break;

            if(bu->flags & OPT_TYPING)
                imcb_buddy_typing(sd->ic, sm->steamid, 0);
            else
                imcb_buddy_typing(sd->ic, sm->steamid, OPT_TYPING);
            break;
        }
    }

    if((ts & STEAM_MESSAGE_TYPE_EMOTE) || (ts & STEAM_MESSAGE_TYPE_SAYTEXT)) {
        sd->timeout = 3;
    } else if(ts & STEAM_MESSAGE_TYPE_TYPING) {
        sd->timeout = 2;
    } else {
        if(sd->timeout < 20)
            sd->timeout++;
    }

    sd->ml_id = b_timeout_add(sd->timeout, steam_main_loop, sd);
}

static char *steam_eval_authcode(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sd;

    g_return_val_if_fail(acc != NULL, value);

    sd = acc->ic->proto_data;

    g_return_if_fail(sd != NULL);

    imcb_log(sd->ic, "Authenticating");
    steam_api_auth(sd->api, value, acc->user, acc->pass,
                   steam_auth_cb, sd);
    return NULL;
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
}

static void steam_login(account_t *acc)
{
    SteamData *sd;
    GRand *rand;
    gchar *umqid;

    umqid = set_getstr(&acc->set, "umqid");
    sd    = steam_data_new(acc, umqid);

    set_setstr(&acc->set, "umqid", sd->api->umqid);

    imcb_log(sd->ic, "Connecting");
    sd->api->token = g_strdup(set_getstr(&acc->set, "token"));

    if(sd->api->token == NULL) {
        steam_api_auth(sd->api, NULL, acc->user, acc->pass, steam_auth_cb, sd);
        return;
    }

    imcb_log(sd->ic, "Resetting UMQID");
    steam_api_logoff(sd->api, steam_reset_cb, sd);
}

static void steam_logout(struct im_connection *ic)
{
    SteamData *sd = ic->proto_data;

    g_return_if_fail(sd != NULL);

    if(sd->ml_id >= 1)
        b_event_remove(sd->ml_id);

    if(ic->flags & OPT_LOGGING_OUT)
        steam_api_logoff(sd->api, steam_logoff_cb, sd);
    else
        steam_data_free(sd);

    sd->ic = NULL;
}

static GList *steam_away_states(struct im_connection *ic)
{
    GList *l = NULL;

    l = g_list_append(l, steam_state_str(STEAM_STATE_AWAY));
    l = g_list_append(l, steam_state_str(STEAM_STATE_BUSY));
    l = g_list_append(l, steam_state_str(STEAM_STATE_SNOOZE));

    return l;
}

static void steam_message_cb(SteamAPI *api, SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    if(err != STEAM_ERROR_SUCCESS)
        imcb_error(sd->ic, steam_api_error_str(err));
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    SteamData *sd = ic->proto_data;
    SteamMessageType type;

    g_return_val_if_fail(sd != NULL, 0);

    if(g_str_has_prefix(message, "/me")) {
        if(strlen(message) < 5)
            return 0;

        type     = STEAM_MESSAGE_TYPE_EMOTE;
        message += 4;
    } else {
        type = STEAM_MESSAGE_TYPE_SAYTEXT;
    }

    steam_api_message(sd->api, to, message, type, steam_message_cb, sd);
    return 0;
}

static void steam_set_away(struct im_connection *ic, char *state,
                           char *message)
{
    /* Set away status if possible via API */
}

static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    SteamData *sd = ic->proto_data;

    g_return_val_if_fail(sd != NULL, 0);

    steam_api_message(sd->api, who, NULL, STEAM_MESSAGE_TYPE_TYPING, NULL, sd);
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

static void steam_user_info_cb(SteamAPI *api, SteamUserInfo *uinfo,
                               SteamError err, gpointer data)
{
    SteamData *sd = data;

    g_return_if_fail(sd != NULL);

    if(sd->ic == NULL)
        return;

    if(err != STEAM_ERROR_SUCCESS) {
        imcb_error(sd->ic, steam_api_error_str(err));
        return;
    }

    if(uinfo->name != NULL)
        imcb_log(sd->ic, "Name:      %s", uinfo->name);

    if(uinfo->realname != NULL)
        imcb_log(sd->ic, "Real Name: %s", uinfo->realname);

    if(uinfo->steamid != NULL)
        imcb_log(sd->ic, "Steam ID:  %s", uinfo->steamid);

    imcb_log(sd->ic, "Status:    %s", steam_state_str(uinfo->state));

    if(uinfo->profile != NULL)
        imcb_log(sd->ic, "Profile:   %s", uinfo->profile);
}

static void steam_get_info(struct im_connection *ic, char *who)
{
    SteamData *sd = ic->proto_data;

    g_return_if_fail(sd != NULL);

    steam_api_user_info(sd->api, who, steam_user_info_cb, sd);
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

    sd->ic  = imcb_new(acc);
    sd->api = steam_api_new(umqid);

    acc->ic = sd->ic;
    sd->ic->proto_data = sd;

    return sd;
}

void steam_data_free(SteamData *sd)
{
    g_return_if_fail(sd != NULL);

    steam_api_free(sd->api);
    g_free(sd);
}
