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

#ifndef __MEGA_RSA_KEY_H__
#define __MEGA_RSA_KEY_H__

#include <mega/mega-aes-key.h>

#define MEGA_TYPE_RSA_KEY            (mega_rsa_key_get_type())
#define MEGA_RSA_KEY(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_RSA_KEY, MegaRsaKey))
#define MEGA_RSA_KEY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_RSA_KEY, MegaRsaKeyClass))
#define MEGA_IS_RSA_KEY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_RSA_KEY))
#define MEGA_IS_RSA_KEY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_RSA_KEY))
#define MEGA_RSA_KEY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_RSA_KEY, MegaRsaKeyClass))

typedef struct _MegaRsaKey MegaRsaKey;
typedef struct _MegaRsaKeyClass MegaRsaKeyClass;
typedef struct _MegaRsaKeyPrivate MegaRsaKeyPrivate;

struct _MegaRsaKey
{
  GObject parent;
  MegaRsaKeyPrivate* priv;
};

struct _MegaRsaKeyClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_rsa_key_get_type           (void) G_GNUC_CONST;

MegaRsaKey*             mega_rsa_key_new                (void);
gchar*                  mega_rsa_key_encrypt            (MegaRsaKey* rsa_key, const guchar* data, gsize len);
GBytes*                 mega_rsa_key_decrypt            (MegaRsaKey* rsa_key, const gchar* cipher);
gboolean                mega_rsa_key_load_enc_privk     (MegaRsaKey* rsa_key, const gchar* privk, MegaAesKey* enc_key);
gboolean                mega_rsa_key_load_pubk          (MegaRsaKey* rsa_key, const gchar* pubk);
gchar*                  mega_rsa_key_get_pubk           (MegaRsaKey* rsa_key);
gchar*                  mega_rsa_key_get_enc_privk      (MegaRsaKey* rsa_key, MegaAesKey* enc_key);
gboolean                mega_rsa_key_generate           (MegaRsaKey* rsa_key);
gchar*                  mega_rsa_key_decrypt_sid        (MegaRsaKey* rsa_key, const gchar* cipher);

G_END_DECLS

#endif
