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

/**
 * MegaFileKey:
 *
 * File node key is 32 byte data structure, that incldues:
 *
 * - 16 byte AES key
 * - 8 byte nonce
 * - 8 byte Meta MAC calculated from CBC-MACs of all file chunks
 *
 * #MegaFileKey is derived from #MegaAesKey. You should not use load methods
 * from #MegaAesKey directly, otherwise the key will become inconsistent.
 */

#include "mega-file-key.h"
#include "utils.h"
#include <string.h>

struct _MegaFileKeyPrivate
{
  guchar key[32];
};

// {{{ GObject property and signal enums
//
enum MegaFileKeyProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaFileKeySignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

#define DW(p, n) (*((guint32*)(p) + (n)))

static void unpack_node_key(guchar node_key[32], guchar aes_key[16], guchar nonce[8], guchar meta_mac_xor[8])
{
  if (aes_key)
  {
    DW(aes_key, 0) = DW(node_key, 0) ^ DW(node_key, 4);
    DW(aes_key, 1) = DW(node_key, 1) ^ DW(node_key, 5);
    DW(aes_key, 2) = DW(node_key, 2) ^ DW(node_key, 6);
    DW(aes_key, 3) = DW(node_key, 3) ^ DW(node_key, 7);
  }

  if (nonce)
  {
    DW(nonce, 0) = DW(node_key, 4);
    DW(nonce, 1) = DW(node_key, 5);
  }

  if (meta_mac_xor)
  {
    DW(meta_mac_xor, 0) = DW(node_key, 6);
    DW(meta_mac_xor, 1) = DW(node_key, 7);
  }
}

G_GNUC_UNUSED
static void pack_node_key(guchar node_key[32], guchar aes_key[16], guchar nonce[8], guchar meta_mac[16])
{
  DW(node_key, 0) = DW(aes_key, 0) ^ DW(nonce, 0);
  DW(node_key, 1) = DW(aes_key, 1) ^ DW(nonce, 1);
  DW(node_key, 2) = DW(aes_key, 2) ^ DW(meta_mac, 0) ^ DW(meta_mac, 1);
  DW(node_key, 3) = DW(aes_key, 3) ^ DW(meta_mac, 2) ^ DW(meta_mac, 3);
  DW(node_key, 4) = DW(nonce, 0);
  DW(node_key, 5) = DW(nonce, 1);
  DW(node_key, 6) = DW(meta_mac, 0) ^ DW(meta_mac, 1);
  DW(node_key, 7) = DW(meta_mac, 2) ^ DW(meta_mac, 3);
}

/**
 * mega_file_key_new:
 *
 * Create new #MegaFileKey object.
 *
 * Returns: #MegaFileKey object.
 */
MegaFileKey* mega_file_key_new(void)
{
  MegaFileKey *file_key = g_object_new(MEGA_TYPE_FILE_KEY, NULL);

  return file_key;
}

/**
 * mega_file_key_load_ubase64:
 * @file_key: a #MegaFileKey
 * @data: UBase64 encoded 32 byte File key data
 *
 * Initialize key from #data.
 *
 * Returns: TRUE on success.
 */
gboolean mega_file_key_load_ubase64(MegaFileKey* file_key, const gchar* data)
{
  gsize len;
  guchar* key;
  guchar aes_key_binary[16];

  g_return_val_if_fail(MEGA_IS_FILE_KEY(file_key), FALSE);
  g_return_val_if_fail(data != NULL, FALSE);

  key = mega_base64urldecode(data, &len);
  if (key == NULL || len != sizeof(file_key->priv->key))
  {
    g_free(key);
    return FALSE;
  }

  memcpy(file_key->priv->key, key, sizeof(file_key->priv->key));

  // load underlying aes key
  unpack_node_key(file_key->priv->key, aes_key_binary, NULL, NULL);
  mega_aes_key_load_binary(MEGA_AES_KEY(file_key), aes_key_binary);

  return TRUE;
}

/**
 * mega_file_key_load_enc_ubase64:
 * @file_key: a #MegaFileKey
 * @data: UBase64 encoded 32 byte File key data
 * @dec_key: Decryption key
 *
 * Initialize key from encrypted #data.
 *
 * Returns: TRUE on success.
 */
gboolean mega_file_key_load_enc_ubase64(MegaFileKey* file_key, const gchar* data, MegaAesKey* dec_key)
{
  guchar aes_key_binary[16];

  g_return_val_if_fail(MEGA_IS_FILE_KEY(file_key), FALSE);
  g_return_val_if_fail(data != NULL, FALSE);
  g_return_val_if_fail(MEGA_IS_AES_KEY(dec_key), FALSE);

  GBytes* bytes = mega_aes_key_decrypt(dec_key, data);
  if (!bytes)
    return FALSE;

  if (g_bytes_get_size(bytes) != sizeof(file_key->priv->key))
    return FALSE;

  memcpy(file_key->priv->key, g_bytes_get_data(bytes, NULL), sizeof(file_key->priv->key));
  g_bytes_unref(bytes);

  unpack_node_key(file_key->priv->key, aes_key_binary, NULL, NULL);

  mega_aes_key_load_binary(MEGA_AES_KEY(file_key), aes_key_binary);

  return TRUE;
}

/**
 * mega_file_key_get_ubase64:
 * @file_key: a #MegaFileKey
 *
 * Get UBase64 encoded key data.
 *
 * Returns: UBase64 encoded string.
 */
gchar* mega_file_key_get_ubase64(MegaFileKey* file_key)
{
  g_return_val_if_fail(MEGA_IS_FILE_KEY(file_key), NULL);

  return mega_base64urlencode(file_key->priv->key, sizeof(file_key->priv->key));
}

/**
 * mega_file_key_get_enc_ubase64:
 * @file_key: a #MegaFileKey
 * @enc_key: AES encryption key.
 *
 * Get UBase64 encoded key data encrypted with #enc_key.
 *
 * Returns: UBase64 encoded string.
 */
gchar* mega_file_key_get_enc_ubase64(MegaFileKey* file_key, MegaAesKey* enc_key)
{
  g_return_val_if_fail(MEGA_IS_FILE_KEY(file_key), NULL);
  g_return_val_if_fail(MEGA_IS_AES_KEY(enc_key), NULL);

  return mega_aes_key_encrypt(enc_key, file_key->priv->key, sizeof(file_key->priv->key));
}

/**
 * mega_file_key_generate:
 * @file_key: a #MegaFileKey
 *
 * Generate new file key and nonce, clear meta mac.
 */
void mega_file_key_generate(MegaFileKey* file_key)
{
  guchar meta_mac[16];
  guchar* aes_key;
  guchar nonce[8];

  g_return_if_fail(MEGA_IS_FILE_KEY(file_key));

  // clear meta mac (can be set later by set_mac)
  memset(meta_mac, 0, sizeof(meta_mac));

  mega_randomness(nonce, sizeof(nonce));
  mega_aes_key_generate(MEGA_AES_KEY(file_key));
  aes_key = mega_aes_key_get_binary(MEGA_AES_KEY(file_key));

  pack_node_key(file_key->priv->key, aes_key, nonce, meta_mac);

  g_free(aes_key);
}

/**
 * mega_file_key_get_nonce:
 * @file_key: a #MegaFileKey
 * @nonce: (out caller-allocates) (element-type guint8) (array fixed-size=8): Nonce
 *
 * Get 8 byte nonce binary data.
 */
void mega_file_key_get_nonce(MegaFileKey* file_key, guchar* nonce)
{
  g_return_if_fail(MEGA_IS_FILE_KEY(file_key));
  g_return_if_fail(nonce != NULL);

  unpack_node_key(file_key->priv->key, NULL, nonce, NULL);
}

/**
 * mega_file_key_check_mac:
 * @file_key: a #MegaFileKey
 * @mac: #MegaChunkedCbcMac to check against.
 *
 * Check file key against calculated #mac.
 *
 * Returns: TRUE if #mac matches the one stored in the key.
 */
gboolean mega_file_key_check_mac(MegaFileKey* file_key, MegaChunkedCbcMac* mac)
{
  guchar meta_mac[8];
  guchar meta_mac_key[8];
  guchar buf[16];
  gint i;

  g_return_val_if_fail(MEGA_IS_FILE_KEY(file_key), FALSE);
  g_return_val_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac), FALSE);

  unpack_node_key(file_key->priv->key, NULL, NULL, meta_mac_key);

  mega_chunked_cbc_mac_finish(mac, buf);

  for (i = 0; i < 4; i++)
    meta_mac[i] = buf[i] ^ buf[i + 4];
  for (i = 0; i < 4; i++)
    meta_mac[i + 4] = buf[i + 8] ^ buf[i + 12];

  return memcmp(meta_mac, meta_mac_key, 8) == 0;
}

/**
 * mega_file_key_set_mac:
 * @file_key: a #MegaFileKey
 * @mac: #MegaChunkedCbcMac to store in the key
 *
 * Write #mac into the key.
 */
void mega_file_key_set_mac(MegaFileKey* file_key, MegaChunkedCbcMac* mac)
{
  guchar meta_mac[16];
  guchar aes_key[16];
  guchar nonce[8];

  g_return_if_fail(MEGA_IS_FILE_KEY(file_key));
  g_return_if_fail(MEGA_IS_CHUNKED_CBC_MAC(mac));

  mega_chunked_cbc_mac_finish(mac, meta_mac);

  unpack_node_key(file_key->priv->key, aes_key, nonce, NULL);
  pack_node_key(file_key->priv->key, aes_key, nonce, meta_mac);
}

// {{{ GObject type setup
//
static void mega_file_key_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaFileKey *file_key = MEGA_FILE_KEY(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_file_key_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaFileKey *file_key = MEGA_FILE_KEY(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaFileKey, mega_file_key, MEGA_TYPE_AES_KEY);

static void mega_file_key_init(MegaFileKey *file_key)
{
  file_key->priv = G_TYPE_INSTANCE_GET_PRIVATE(file_key, MEGA_TYPE_FILE_KEY, MegaFileKeyPrivate);
}

static void mega_file_key_dispose(GObject *object)
{
  //MegaFileKey *file_key = MEGA_FILE_KEY(object);
  //
  // Free everything that may hold reference to MegaFileKey
  //
  G_OBJECT_CLASS(mega_file_key_parent_class)->dispose(object);
}

static void mega_file_key_finalize(GObject *object)
{
  //MegaFileKey *file_key = MEGA_FILE_KEY(object);
  //
  G_OBJECT_CLASS(mega_file_key_parent_class)->finalize(object);
}

static void mega_file_key_class_init(MegaFileKeyClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_file_key_set_property;
  gobject_class->get_property = mega_file_key_get_property;

  gobject_class->dispose = mega_file_key_dispose;
  gobject_class->finalize = mega_file_key_finalize;

  g_type_class_add_private(klass, sizeof(MegaFileKeyPrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
