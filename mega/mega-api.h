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

#ifndef __MEGA_API_H__
#define __MEGA_API_H__

#include <glib-object.h>

#define MEGA_TYPE_API            (mega_api_get_type())
#define MEGA_API(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_API, MegaApi))
#define MEGA_API_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_API, MegaApiClass))
#define MEGA_IS_API(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_API))
#define MEGA_IS_API_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_API))
#define MEGA_API_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_API, MegaApiClass))

typedef struct _MegaApi MegaApi;
typedef struct _MegaApiClass MegaApiClass;
typedef struct _MegaApiPrivate MegaApiPrivate;

struct _MegaApi
{
  GObject parent;
  MegaApiPrivate* priv;
};

struct _MegaApiClass
{
  GObjectClass parent_class;
};

// just for reference in client apps
typedef enum {
  MEGA_API_SERVER_ERROR_EINTERNAL = -1,
  MEGA_API_SERVER_ERROR_EARGS = -2,
  MEGA_API_SERVER_ERROR_EAGAIN = -3,
  MEGA_API_SERVER_ERROR_ERATELIMIT = -4,
  MEGA_API_SERVER_ERROR_EFAILED = -5,
  MEGA_API_SERVER_ERROR_ETOOMANY = -6,
  MEGA_API_SERVER_ERROR_ERANGE = -7,
  MEGA_API_SERVER_ERROR_EEXPIRED = -8,
  MEGA_API_SERVER_ERROR_ENOENT = -9,
  MEGA_API_SERVER_ERROR_ECIRCULAR = -10,
  MEGA_API_SERVER_ERROR_EACCESS = -11,
  MEGA_API_SERVER_ERROR_EEXIST = -12,
  MEGA_API_SERVER_ERROR_EINCOMPLETE = -13,
  MEGA_API_SERVER_ERROR_EKEY = -14,
  MEGA_API_SERVER_ERROR_ESID = -15,
  MEGA_API_SERVER_ERROR_EBLOCKED = -16,
  MEGA_API_SERVER_ERROR_EOVERQUOTA = -17,
  MEGA_API_SERVER_ERROR_ETEMPUNAVAIL = -18,
  MEGA_API_SERVER_ERROR_ETOOMANYCONNECTIONS = -19
} MegaApiServerError;

#define MEGA_API_ERROR mega_api_error_quark()

typedef enum 
{
  MEGA_API_ERROR_TIMEOUT,

  MEGA_API_ERROR_EINTERNAL,
  MEGA_API_ERROR_EARGS,
  MEGA_API_ERROR_EAGAIN,
  MEGA_API_ERROR_ERATELIMIT,
  MEGA_API_ERROR_EFAILED,
  MEGA_API_ERROR_ETOOMANY,
  MEGA_API_ERROR_ERANGE,
  MEGA_API_ERROR_EEXPIRED,
  MEGA_API_ERROR_ENOENT,
  MEGA_API_ERROR_ECIRCULAR,
  MEGA_API_ERROR_EACCESS,
  MEGA_API_ERROR_EEXIST,
  MEGA_API_ERROR_EINCOMPLETE,
  MEGA_API_ERROR_EKEY,
  MEGA_API_ERROR_ESID,
  MEGA_API_ERROR_EBLOCKED,
  MEGA_API_ERROR_EOVERQUOTA,
  MEGA_API_ERROR_ETEMPUNAVAIL,
  MEGA_API_ERROR_ETOOMANYCONNECTIONS,

  MEGA_API_ERROR_OTHER
} MegaApiError;

G_BEGIN_DECLS

GQuark                  mega_api_error_quark            (void);

GType                   mega_api_get_type               (void) G_GNUC_CONST;

MegaApi*                mega_api_new                    (void);
gchar*                  mega_api_call                   (MegaApi* api, const gchar* request, GError** error);
gchar*                  mega_api_call_simple            (MegaApi* api, gchar expects, GError** error, const gchar* format, ...);

G_END_DECLS

#endif
