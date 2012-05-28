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

#include "steam-api.h"

static void steam_init(account_t *acc)
{
    
}

static void steam_login(account_t *acc)
{
    struct im_connection *ic  = imcb_new(acc);
    
    acc->ic        = ic;
}

static void steam_logout(struct im_connection *ic)
{
    
}

static int steam_buddy_msg(struct im_connection *ic, char *to, char *message,
                           int flags)
{
    return 0;
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

void steam_initmodule()
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
    
    register_protocol(ret);
}
