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

#ifndef __MEGA_AES_KEY_H__
#define __MEGA_AES_KEY_H__

#include <glib-object.h>

#define MEGA_TYPE_AES_KEY            (mega_aes_key_get_type())
#define MEGA_AES_KEY(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_AES_KEY, MegaAesKey))
#define MEGA_AES_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_AES_KEY, MegaAesKeyClass))
#define MEGA_IS_AES_KEY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_AES_KEY))
#define MEGA_IS_AES_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_AES_KEY))
#define MEGA_AES_KEY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_AES_KEY, MegaAesKeyClass))

typedef struct _MegaAesKey MegaAesKey;
typedef struct _MegaAesKeyClass MegaAesKeyClass;
typedef struct _MegaAesKeyPrivate MegaAesKeyPrivate;

struct _MegaAesKey
{
  GObject parent;
  MegaAesKeyPrivate* priv;
};

struct _MegaAesKeyClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_aes_key_get_type           (void) G_GNUC_CONST;

// construction helpers

MegaAesKey*             mega_aes_key_new                (void);

MegaAesKey*             mega_aes_key_new_generated      (void);
MegaAesKey*             mega_aes_key_new_from_password  (const gchar* password);

MegaAesKey*             mega_aes_key_new_from_binary    (const guchar* data);
MegaAesKey*             mega_aes_key_new_from_ubase64   (const gchar* data);
MegaAesKey*             mega_aes_key_new_from_enc_binary(const guchar* data, MegaAesKey* dec_key);
MegaAesKey*             mega_aes_key_new_from_enc_ubase64(const gchar* data, MegaAesKey* dec_key);

// loaders

void                    mega_aes_key_load_binary        (MegaAesKey* aes_key, const guchar* data);
gboolean                mega_aes_key_load_ubase64       (MegaAesKey* aes_key, const gchar* data);
void                    mega_aes_key_load_enc_binary    (MegaAesKey* aes_key, const guchar* data, MegaAesKey* dec_key);
gboolean                mega_aes_key_load_enc_ubase64   (MegaAesKey* aes_key, const gchar* data, MegaAesKey* dec_key);

gboolean                mega_aes_key_is_loaded          (MegaAesKey* aes_key);

// generators

void                    mega_aes_key_generate_from_password(MegaAesKey* aes_key, const gchar* password);
void                    mega_aes_key_generate           (MegaAesKey* aes_key);

// getters

guchar*                 mega_aes_key_get_binary         (MegaAesKey* aes_key);
gchar*                  mega_aes_key_get_ubase64        (MegaAesKey* aes_key);
guchar*                 mega_aes_key_get_enc_binary     (MegaAesKey* aes_key, MegaAesKey* enc_key);
gchar*                  mega_aes_key_get_enc_ubase64    (MegaAesKey* aes_key, MegaAesKey* enc_key);

// operations

void                    mega_aes_key_encrypt_raw        (MegaAesKey* aes_key, const guchar* plain, guchar* cipher, gsize len);
void                    mega_aes_key_decrypt_raw        (MegaAesKey* aes_key, const guchar* cipher, guchar* plain, gsize len);

gchar*                  mega_aes_key_encrypt            (MegaAesKey* aes_key, const guchar* plain, gsize len);
GBytes*                 mega_aes_key_decrypt            (MegaAesKey* aes_key, const gchar* cipher);

gchar*                  mega_aes_key_encrypt_cbc        (MegaAesKey* aes_key, const guchar* plain, gsize len);
gchar*                  mega_aes_key_encrypt_string_cbc (MegaAesKey* aes_key, const gchar* str);
GBytes*                 mega_aes_key_decrypt_cbc        (MegaAesKey* aes_key, const gchar* cipher);

void                    mega_aes_key_encrypt_cbc_raw    (MegaAesKey* aes_key, const guchar* plain, guchar* cipher, gsize len);
void                    mega_aes_key_decrypt_cbc_raw    (MegaAesKey* aes_key, const guchar* cipher, guchar* plain, gsize len);

void                    mega_aes_key_setup_ctr          (MegaAesKey* aes_key, guchar* nonce, guint64 position);
void                    mega_aes_key_encrypt_ctr        (MegaAesKey* aes_key, guchar* from, guchar* to, gsize len);

gchar*                  mega_aes_key_make_username_hash (MegaAesKey* aes_key, const gchar* username);

G_END_DECLS

#endif
