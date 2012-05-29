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

static void steam_logon_cb(SteamAPI * api, SteamError err, gpointer data)
{
    SteamData *sd = data;
    gboolean cont;
    
    switch(err) {
    case STEAM_ERROR_SUCCESS:
        //imcb_connected(sd->ic);
        return;
    
    case STEAM_ERROR_LOGON_INVALID:
        cont = FALSE;
        break;
    
    default:
        cont = TRUE;
        break;
    }
    
    imcb_error(sd->ic, steam_api_error_str(err));
    imc_logout(sd->ic, cont);
}

static void steam_auth_cb(SteamAPI * api, SteamError err, gpointer data)
{
    SteamData *sd = data;
    gchar *msg;
    
    account_t *acc;
    guint i;
    
    switch(err) {
    case STEAM_ERROR_SUCCESS:
        set_setstr(&sd->acc->set, "token", api->token);
        imcb_log(sd->ic, "Authentication finished");
        steam_api_logon(api, steam_logon_cb, NULL);
        break;
    
    case STEAM_ERROR_AUTH_CODE_INVALID:
        imcb_error(sd->ic, "SteamGuard authentication code invalid");
        imc_logout(sd->ic, FALSE);
        break;
    
    case STEAM_ERROR_AUTH_CODE_REQ:
        acc = sd->acc->bee->accounts;
        
        for(i = 0; acc != NULL; acc = acc->next, i++) {
            if(sd->acc == acc)
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

static char *steam_eval_authcode(set_t *set, char *value)
{
    account_t *acc = set->data;
    SteamData *sd  = acc->ic->proto_data;
    
    steam_api_auth(sd->api, value, steam_auth_cb, sd);
    return NULL;
}

static void steam_init(account_t *acc)
{
    set_t *s;
    
    s = set_add(&acc->set, "token", NULL, NULL, acc);
    s->flags = SET_HIDDEN;
    
    s = set_add(&acc->set, "authcode", NULL, steam_eval_authcode, acc);
    s->flags = SET_NOSAVE | SET_NULL_OK | SET_HIDDEN;
}

static void steam_login(account_t *acc)
{
    struct im_connection *ic  = imcb_new(acc);
    SteamData            *sd  = g_new0(SteamData, 1);
    
    sd->acc    = acc;
    sd->ic     = ic;
    sd->api    = steam_api_new(acc);
    sd->prefix = "steam";
    
    sd->api->token = set_getstr(&acc->set, "token");
    
    ic->proto_data = sd;
    acc->ic        = ic;
    
    if(sd->api->token == NULL) {
        steam_api_auth(sd->api, NULL, steam_auth_cb, sd);
        return;
    }
    
    steam_api_logon(sd->api, steam_logon_cb, sd);
}

static void steam_logoff_cb(SteamAPI * api, SteamError err, gpointer data)
{
    SteamData *sd = data;
    
    if(err != STEAM_ERROR_SUCCESS)
        imcb_error(sd->ic, steam_api_error_str(err));
    
    steam_api_free(sd->api);
    g_free(sd);
}

static void steam_logout(struct im_connection *ic)
{
    SteamData *sd = ic->proto_data;
    
    if(sd->api->token != NULL) {
        steam_api_logoff(sd->api, steam_logoff_cb, sd);
        return;
    }
    
    steam_api_free(sd->api);
    g_free(sd);
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    //steam_api_auth(sd->api, message, steam_auth_cb, sd);
}

static void steam_set_away(struct im_connection *ic, char *state,
                           char *message)
{
    
}

static void steam_get_away(struct im_connection *ic, char *who)
{
    
}

static int steam_send_typing(struct im_connection *ic, char *who, int flags)
{
    return 0;
}

static void steam_add_buddy(struct im_connection *ic, char *name, char * group)
{
    
}

static void steam_remove_buddy(struct im_connection *ic, char *name,
                               char * group)
{
    
}

static void steam_get_info(struct im_connection *ic, char *who)
{
    
}

static void steam_set_my_name(struct im_connection *ic, char *name)
{
    
}

static void steam_chat_invite(struct groupchat *c, char *who, char *message)
{
    
}

static void steam_chat_leave(struct groupchat *c)
{
    
}

static void steam_chat_msg(struct groupchat *c, char *message, int flags)
{
    
}

static struct groupchat *steam_chat_with(struct im_connection *ic, char *who)
{
    return NULL;
}

static struct groupchat *steam_chat_join(struct im_connection *ic,
                                         const char *room, const char *nick,
                                         const char *password, set_t **sets)
{
    return NULL;
}

static void steam_chat_topic(struct groupchat *c, char *topic)
{
    
}

static GList *steam_away_states(struct im_connection *ic)
{
    return NULL;
}

static void steam_buddy_data_add(struct bee_user *bu)
{
    
}

static void steam_buddy_data_free(struct bee_user *bu)
{
    
}

static GList *steam_buddy_action_list(struct bee_user *bu)
{
    return NULL;
}

static void *steam_buddy_action(struct bee_user *bu, const char *action,
                                char * const args[], void *data)
{
    return NULL;
}

void init_plugin()
{
    struct prpl *ret = g_new0(struct prpl, 1);
    
    ret->name              = "steam";
    ret->mms               = 0;
    ret->init              = steam_init;
    ret->login             = steam_login;
    ret->logout            = steam_logout;
    ret->buddy_msg         = steam_buddy_msg;
    ret->set_away          = steam_set_away;
    ret->get_away          = steam_get_away;
    ret->send_typing       = steam_send_typing;
    ret->add_buddy         = steam_add_buddy;
    ret->remove_buddy      = steam_remove_buddy;
    ret->get_info          = steam_get_info;
    ret->chat_invite       = steam_chat_invite;
    ret->chat_leave        = steam_chat_leave;
    ret->chat_msg          = steam_chat_msg;
    ret->chat_with         = steam_chat_with;
    ret->chat_join         = steam_chat_join;
    ret->chat_topic        = steam_chat_topic;
    ret->away_states       = steam_away_states;
    ret->buddy_data_add    = steam_buddy_data_add;
    ret->buddy_data_free   = steam_buddy_data_free;
    ret->buddy_action_list = steam_buddy_action_list;
    ret->buddy_action      = steam_buddy_action;
    ret->handle_cmp        = g_strcmp0;
    
    register_protocol(ret);
}
