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

#ifndef __MEGA_FILE_KEY_H__
#define __MEGA_FILE_KEY_H__

#include <mega/mega-aes-key.h>
#include <mega/mega-chunked-cbc-mac.h>

#define MEGA_TYPE_FILE_KEY            (mega_file_key_get_type())
#define MEGA_FILE_KEY(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_FILE_KEY, MegaFileKey))
#define MEGA_FILE_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_FILE_KEY, MegaFileKeyClass))
#define MEGA_IS_FILE_KEY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_FILE_KEY))
#define MEGA_IS_FILE_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_FILE_KEY))
#define MEGA_FILE_KEY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_FILE_KEY, MegaFileKeyClass))

typedef struct _MegaFileKey MegaFileKey;
typedef struct _MegaFileKeyClass MegaFileKeyClass;
typedef struct _MegaFileKeyPrivate MegaFileKeyPrivate;

struct _MegaFileKey
{
  MegaAesKey parent;
  MegaFileKeyPrivate* priv;
};

struct _MegaFileKeyClass
{
  MegaAesKeyClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_file_key_get_type          (void) G_GNUC_CONST;

MegaFileKey*            mega_file_key_new               (void);

gboolean                mega_file_key_load_ubase64      (MegaFileKey* file_key, const gchar* data);
gboolean                mega_file_key_load_enc_ubase64  (MegaFileKey* file_key, const gchar* data, MegaAesKey* dec_key);
gchar*                  mega_file_key_get_ubase64       (MegaFileKey* file_key);
gchar*                  mega_file_key_get_enc_ubase64   (MegaFileKey* file_key, MegaAesKey* enc_key);

void                    mega_file_key_generate          (MegaFileKey* file_key);

void                    mega_file_key_get_nonce         (MegaFileKey* file_key, guchar* nonce);
gboolean                mega_file_key_check_mac         (MegaFileKey* file_key, MegaChunkedCbcMac* mac);
void                    mega_file_key_set_mac           (MegaFileKey* file_key, MegaChunkedCbcMac* mac);

G_END_DECLS

#endif
