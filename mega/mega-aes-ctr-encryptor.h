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

#ifndef __MEGA_AES_CTR_ENCRYPTOR_H__
#define __MEGA_AES_CTR_ENCRYPTOR_H__

#include <gio/gio.h>
#include <mega/mega-file-key.h>

#define MEGA_TYPE_AES_CTR_ENCRYPTOR            (mega_aes_ctr_encryptor_get_type())
#define MEGA_AES_CTR_ENCRYPTOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_AES_CTR_ENCRYPTOR, MegaAesCtrEncryptor))
#define MEGA_AES_CTR_ENCRYPTOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_AES_CTR_ENCRYPTOR, MegaAesCtrEncryptorClass))
#define MEGA_IS_AES_CTR_ENCRYPTOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_AES_CTR_ENCRYPTOR))
#define MEGA_IS_AES_CTR_ENCRYPTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_AES_CTR_ENCRYPTOR))
#define MEGA_AES_CTR_ENCRYPTOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_AES_CTR_ENCRYPTOR, MegaAesCtrEncryptorClass))

typedef struct _MegaAesCtrEncryptor MegaAesCtrEncryptor;
typedef struct _MegaAesCtrEncryptorClass MegaAesCtrEncryptorClass;
typedef struct _MegaAesCtrEncryptorPrivate MegaAesCtrEncryptorPrivate;

typedef enum
{
  MEGA_AES_CTR_ENCRYPTOR_DIRECTION_ENCRYPT,
  MEGA_AES_CTR_ENCRYPTOR_DIRECTION_DECRYPT
} MegaAesCtrEncryptorDirection;

struct _MegaAesCtrEncryptor
{
  GObject parent;
  MegaAesCtrEncryptorPrivate* priv;
};

struct _MegaAesCtrEncryptorClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_aes_ctr_encryptor_get_type (void) G_GNUC_CONST;

MegaAesCtrEncryptor*    mega_aes_ctr_encryptor_new      (void);
void                    mega_aes_ctr_encryptor_set_key  (MegaAesCtrEncryptor* aes_ctr_encryptor, MegaFileKey* key);
void                    mega_aes_ctr_encryptor_set_position(MegaAesCtrEncryptor* aes_ctr_encryptor, guint64 position);
void                    mega_aes_ctr_encryptor_set_mac  (MegaAesCtrEncryptor* aes_ctr_encryptor, MegaChunkedCbcMac* mac, MegaAesCtrEncryptorDirection dir);

G_END_DECLS

#endif
