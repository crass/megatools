/*
 *  megatools - Mega.co.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __MEGA_SESSION_H__
#define __MEGA_SESSION_H__

#include <glib-object.h>

#define MEGA_TYPE_SESSION            (mega_session_get_type())
#define MEGA_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_SESSION, MegaSession))
#define MEGA_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_SESSION, MegaSessionClass))
#define MEGA_IS_SESSION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_SESSION))
#define MEGA_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_SESSION))
#define MEGA_SESSION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_SESSION, MegaSessionClass))

typedef struct _MegaSession MegaSession;
typedef struct _MegaSessionClass MegaSessionClass;
typedef struct _MegaSessionPrivate MegaSessionPrivate;

struct _MegaSession
{
  GObject parent;
  MegaSessionPrivate* priv;
};

struct _MegaSessionClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_session_get_type           (void) G_GNUC_CONST;

MegaSession*            mega_session_new                (void);
gboolean                mega_session_open               (MegaSession* session, const gchar* username, const gchar* password, const gchar* session_id, GError** error);
gboolean                mega_session_login              (MegaSession* session, const gchar* username, const gchar* password, GError** error);
gboolean                mega_session_logout             (MegaSession* session, GError** error);
gboolean                mega_session_close              (MegaSession* session);
gboolean                mega_session_save               (MegaSession* session, GError** error);
gboolean                mega_session_load               (MegaSession* session, const gchar* username, const gchar* password, GError** error);
gboolean                mega_session_get_user_info      (MegaSession* session, GError** error);

G_END_DECLS

#endif
