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
 * MegaRsaKey:
 *
 * 2048 bit RSA key is used for authentication and sharing file keys between
 * users of Mega.co.nz.
 *
 * This object allows you to load RSA key in mega's format, and use it for
 * encryption/decryption.
 *
 * It is also possible to generate new RSA key, for example if you want to
 * change it, or register new Mega.co.nz account.
 *
 * There is also a helper method provided to simplify decryption of session id
 * during authentication.
 */

#include "mega-rsa-key.h"
#include "utils.h"

#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

struct _MegaRsaKeyPrivate
{
  // priv
  BIGNUM* p;
  BIGNUM* q;
  BIGNUM* d;
  BIGNUM* u; // p^-1 mod q
  // pub
  BIGNUM* m;
  BIGNUM* e;
};

// {{{ GObject property and signal enums
//
enum MegaRsaKeyProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaRsaKeySignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

#define MPI_SET_BITS(ptr, bits) *(guint16*)(ptr) = GUINT16_TO_BE(bits)
#define MPI_BITS(ptr) GUINT16_FROM_BE(*(guint16*)(ptr))
#define MPI_BYTES(ptr) ((MPI_BITS(ptr) + 7) / 8)
#define MPI_SIZE(ptr) (MPI_BYTES(ptr) + MPI_HDRSIZE)
#define MPI_HDRSIZE 2
#define MPI2BN(ptr) \
  BN_bin2bn((ptr) + MPI_HDRSIZE, MPI_BYTES(ptr), NULL)

static void append_mpi_from_bn(GString* buf, BIGNUM* n)
{
  g_return_if_fail(buf != NULL);
  g_return_if_fail(n != NULL);

  gsize size = BN_num_bytes(n);
  gsize off = buf->len;

  g_string_set_size(buf, buf->len + size + MPI_HDRSIZE);

  MPI_SET_BITS(buf->str + off, BN_num_bits(n));
  BN_bn2bin(n, buf->str + off + MPI_HDRSIZE);
}

static void clear_pub_key(MegaRsaKey* rsa_key)
{
  MegaRsaKeyPrivate* priv = rsa_key->priv;

  if (priv->m) BN_free(priv->m);
  if (priv->e) BN_free(priv->e);

  priv->m = priv->e = NULL;
}

static void clear_priv_key(MegaRsaKey* rsa_key)
{
  MegaRsaKeyPrivate* priv = rsa_key->priv;

  if (priv->p) BN_free(priv->p);
  if (priv->q) BN_free(priv->q);
  if (priv->d) BN_free(priv->d);
  if (priv->u) BN_free(priv->u);

  priv->p = priv->q = priv->d = priv->u = NULL;
}

static BIGNUM* rsa_decrypt(BIGNUM* m, BIGNUM* d, BIGNUM* p, BIGNUM* q, BIGNUM* u)
{
  BN_CTX* ctx;
  BIGNUM *xp, *mod_mp, *mod_dp1, *p1, *xq, *mod_mq, *mod_dq1, *q1, *t, *x;

  g_return_val_if_fail(m != NULL, NULL);
  g_return_val_if_fail(d != NULL, NULL);
  g_return_val_if_fail(p != NULL, NULL);
  g_return_val_if_fail(q != NULL, NULL);
  g_return_val_if_fail(u != NULL, NULL);

  ctx = BN_CTX_new();

  xp = BN_new();
  xq = BN_new();
  mod_mp = BN_new();
  mod_mq = BN_new();
  mod_dp1 = BN_new();
  mod_dq1 = BN_new();
  p1 = BN_new();
  q1 = BN_new();
  t = BN_new();
  x = BN_new();

  // var xp = bmodexp(bmod(m,p), bmod(d,bsub(p,[1])), p);
  BN_mod(mod_mp, m, p, ctx);
  BN_sub(p1, p, BN_value_one());
  BN_mod(mod_dp1, d, p1, ctx);
  BN_mod_exp(xp, mod_mp, mod_dp1, p, ctx);

  // var xq = bmodexp(bmod(m,q), bmod(d,bsub(q,[1])), q);
  BN_mod(mod_mq, m, q, ctx);
  BN_sub(q1, q, BN_value_one());
  BN_mod(mod_dq1, d, q1, ctx);
  BN_mod_exp(xq, mod_mq, mod_dq1, q, ctx);

  // var t = bsub(xq,xp);
  if (BN_ucmp(xq, xp) <= 0)
  {
    BN_sub(t, xp, xq);
    BN_mul(x, t, u, ctx);
    BN_mod(t, x, q, ctx);
    BN_sub(t, q, t);
  }
  else
  {
    BN_sub(t, xq, xp);
    BN_mul(x, t, u, ctx);
    BN_mod(t, x, q, ctx);
  }

  BN_mul(x, t, p, ctx);
  BN_add(x, x, xp);

  BN_free(xp);
  BN_free(xq);
  BN_free(mod_mp);
  BN_free(mod_mq);
  BN_free(mod_dp1);
  BN_free(mod_dq1);
  BN_free(p1);
  BN_free(q1);
  BN_free(t);

  BN_CTX_free(ctx);

  return x;
}

static BIGNUM* rsa_encrypt(BIGNUM* s, BIGNUM* e, BIGNUM* m)
{
  BN_CTX* ctx;
  BIGNUM *r;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(e != NULL, NULL);
  g_return_val_if_fail(m != NULL, NULL);

  ctx = BN_CTX_new();
  r = BN_new();

  BN_mod_exp(r, s, e, m, ctx);

  BN_CTX_free(ctx);

  return r;
}

/**
 * mega_rsa_key_new:
 *
 * Create new #MegaRsaKey object.
 *
 * Returns: #MegaRsaKey object.
 */
MegaRsaKey* mega_rsa_key_new(void)
{
  MegaRsaKey *rsa_key = g_object_new(MEGA_TYPE_RSA_KEY, NULL);

  return rsa_key;
}

/**
 * mega_rsa_key_encrypt:
 * @rsa_key: a #MegaRsaKey
 * @data: (element-type guint8) (array length=len) (transfer none): Plaintext data.
 * @len: Length of the plaintext data (must be less than 256 bytes).
 *
 * Encrypt data (data are random padded to the size of the modulus).
 *
 * Returns: UBase64 encoded MPI.
 */
gchar* mega_rsa_key_encrypt(MegaRsaKey* rsa_key, const guchar* data, gsize len)
{
  BIGNUM *c, *m;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);

  gsize message_length = (BN_num_bits(rsa_key->priv->m) >> 3) - 1;

  // check that data fits the message
  g_return_val_if_fail(len <= message_length, NULL);

  // create random padded message from data
  guchar* message = g_malloc0(message_length);
  memcpy(message, data, len);
  RAND_bytes(message + len, message_length - len);
  m = BN_bin2bn(message, message_length, NULL);
  g_free(message);

  // encrypt mesasge
  c = rsa_encrypt(m, rsa_key->priv->e, rsa_key->priv->m);
  BN_free(m);

  // encode result as MPI
  guchar* cipher_mpi = g_malloc0(BN_num_bytes(c) + MPI_HDRSIZE);
  BN_bn2bin(c, cipher_mpi + MPI_HDRSIZE);
  MPI_SET_BITS(cipher_mpi, BN_num_bits(c));

  // right align 
  gchar* str = mega_base64urlencode(cipher_mpi, BN_num_bytes(c) + MPI_HDRSIZE);

  g_free(cipher_mpi);
  BN_free(c);

  return str;
}

/**
 * mega_rsa_key_decrypt:
 * @rsa_key: a #MegaRsaKey
 * @cipher: UBase64 encoded ciphertext.
 *
 * Decrypt data.
 *
 * Returns: (transfer full): Binary plaintext data (includes random padding).
 */
GBytes* mega_rsa_key_decrypt(MegaRsaKey* rsa_key, const gchar* cipher)
{
  gsize cipherlen = 0;
  guchar* cipher_raw;
  guchar* data;
  BIGNUM *c, *m;
  MegaRsaKeyPrivate* priv;
  gssize message_length;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(cipher != NULL, NULL);

  if (rsa_key->priv->m)
    message_length = (BN_num_bits(rsa_key->priv->m) >> 3) - 1;
  else
    message_length = -1;

  priv = rsa_key->priv;

  cipher_raw = mega_base64urldecode(cipher, &cipherlen);
  if (cipher_raw == NULL)
    return NULL;

  if (MPI_SIZE(cipher_raw) > cipherlen)
  {
    g_free(cipher_raw);
    return NULL;
  }

  c = MPI2BN(cipher_raw);
  g_free(cipher_raw);

  m = rsa_decrypt(c, priv->d, priv->p, priv->q, priv->u);
  BN_free(c);

  if (!m) 
    return NULL;

  if (message_length < 0)
    message_length = BN_num_bytes(m);

  // message doesn't fit message length of the original
  if (message_length < BN_num_bytes(m))
  {
    BN_free(m);
    return NULL;
  }

  data = g_malloc0(message_length);

  // align decoded data to the right side of the message buffer (Mega doesn't do
  // this)
  BN_bn2bin(m, data + (message_length - BN_num_bytes(m)));
  BN_free(m);

  return g_bytes_new_take(data, message_length);
}

/**
 * mega_rsa_key_load_enc_privk:
 * @rsa_key: a #MegaRsaKey
 * @privk: Mega.co.nz formatted AES encrypted private key.
 * @enc_key: AES key used for decryption.
 *
 * Load encrypted private key.
 *
 * Returns: TRUE on success.
 */
gboolean mega_rsa_key_load_enc_privk(MegaRsaKey* rsa_key, const gchar* privk, MegaAesKey* enc_key)
{
  gsize data_len = 0;
  const guchar *p, *e;
  GBytes* bytes;
  MegaRsaKeyPrivate* priv;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);
  g_return_val_if_fail(privk != NULL, FALSE);
  g_return_val_if_fail(enc_key != NULL, FALSE);

  priv = rsa_key->priv;
  clear_priv_key(rsa_key);

  bytes = mega_aes_key_decrypt(enc_key, privk);
  if (!bytes)
    return FALSE;

  p = g_bytes_get_data(bytes, &data_len);;
  e = p + data_len;

  if (p + MPI_SIZE(p) > e)
    goto bounds;
  
  priv->p = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  priv->q = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  priv->d = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  priv->u = MPI2BN(p);

  g_bytes_unref(bytes);
  return TRUE;

bounds:
  g_bytes_unref(bytes);
  return FALSE;
}

/**
 * mega_rsa_key_load_pubk:
 * @rsa_key: a #MegaRsaKey
 * @pubk: Mega.co.nz formatted public key.
 *
 * Load public key.
 *
 * Returns: TRUE on success.
 */
gboolean mega_rsa_key_load_pubk(MegaRsaKey* rsa_key, const gchar* pubk)
{
  gsize data_len = 0;
  guchar *data, *p, *e;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);
  g_return_val_if_fail(pubk != NULL, FALSE);

  clear_pub_key(rsa_key);

  data = mega_base64urldecode(pubk, &data_len);
  if (data == NULL)
    return FALSE;

  p = data;
  e = p + data_len;

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  BN_free(rsa_key->priv->m);
  rsa_key->priv->m = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  BN_free(rsa_key->priv->e);
  rsa_key->priv->e = MPI2BN(p);

  g_free(data);
  return TRUE;

bounds:
  g_free(data);
  return FALSE;
}

/**
 * mega_rsa_key_get_pubk:
 * @rsa_key: a #MegaRsaKey
 *
 * Get public key in Mega.co.nz format.
 *
 * Returns: Public key.
 */
gchar* mega_rsa_key_get_pubk(MegaRsaKey* rsa_key)
{
  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);

  GString* data = g_string_sized_new(128 * 3);

  append_mpi_from_bn(data, rsa_key->priv->m);
  append_mpi_from_bn(data, rsa_key->priv->e);

  gchar* str = mega_base64urlencode(data->str, data->len);

  g_string_free(data, TRUE);

  return str;
}

/**
 * mega_rsa_key_get_enc_privk:
 * @rsa_key: a #MegaRsaKey
 * @enc_key: AES key used for encryption.
 *
 * Get encrypted private key in Mega.co.nz format.
 *
 * Returns: Encrypted private key.
 */
gchar* mega_rsa_key_get_enc_privk(MegaRsaKey* rsa_key, MegaAesKey* enc_key)
{
  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(enc_key != NULL, NULL);

  GString* data = g_string_sized_new(128 * 7);

  // XXX: check

  append_mpi_from_bn(data, rsa_key->priv->p);
  append_mpi_from_bn(data, rsa_key->priv->q);
  append_mpi_from_bn(data, rsa_key->priv->d);
  append_mpi_from_bn(data, rsa_key->priv->u);

  // add random padding
  gsize off = data->len;
  gsize pad = data->len % 16 ? 16 - (data->len % 16) : 0;
  if (pad)
  {
    g_string_set_size(data, data->len + pad);
    RAND_bytes(data->str + off, pad);
  }

  gchar* str = mega_aes_key_encrypt(enc_key, data->str, data->len);

  g_string_free(data, TRUE);

  return str;
}

/**
 * mega_rsa_key_generate:
 * @rsa_key: a #MegaRsaKey
 *
 * Generate new RSA key.
 *
 * Returns: TRUE on success.
 */
gboolean mega_rsa_key_generate(MegaRsaKey* rsa_key)
{
  RSA* key;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);

  key = RSA_generate_key(2048, RSA_3, NULL, NULL);
  if (!key)
    return FALSE;

  if (RSA_check_key(key) != 1)
  {
    RSA_free(key);
    return FALSE;
  }

  clear_priv_key(rsa_key);
  clear_pub_key(rsa_key);

  // private part
  rsa_key->priv->p = BN_dup(key->q);
  rsa_key->priv->q = BN_dup(key->p);
  rsa_key->priv->d = BN_dup(key->d);
  rsa_key->priv->u = BN_dup(key->iqmp);

  // public part
  rsa_key->priv->m = BN_dup(key->n);
  rsa_key->priv->e = BN_dup(key->e);

  RSA_free(key);

  return TRUE;
}

/**
 * mega_rsa_key_decrypt_sid:
 * @rsa_key: a #MegaRsaKey
 * @cipher: Encrypted session id (CSID).
 *
 * Decrypt Mega.co.nz session ID.
 *
 * Returns: Session ID string.
 */
gchar* mega_rsa_key_decrypt_sid(MegaRsaKey* rsa_key, const gchar* cipher)
{
  GBytes* b;
  gchar* sid;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(cipher != NULL, NULL);

  b = mega_rsa_key_decrypt(rsa_key, cipher);
  if (b && g_bytes_get_size(b) >= 43)
  {
    sid = mega_base64urlencode(g_bytes_get_data(b, NULL), 43);
    g_bytes_unref(b);
    return sid;
  }

  if (b)
    g_bytes_unref(b);

  return NULL;
}

// {{{ GObject type setup

static void mega_rsa_key_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_rsa_key_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaRsaKey, mega_rsa_key, G_TYPE_OBJECT);

static void mega_rsa_key_init(MegaRsaKey *rsa_key)
{
  rsa_key->priv = G_TYPE_INSTANCE_GET_PRIVATE(rsa_key, MEGA_TYPE_RSA_KEY, MegaRsaKeyPrivate);
}

static void mega_rsa_key_dispose(GObject *object)
{
  //MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);
  //
  // Free everything that may hold reference to MegaRsaKey
  //
  G_OBJECT_CLASS(mega_rsa_key_parent_class)->dispose(object);
}

static void mega_rsa_key_finalize(GObject *object)
{
  MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);

  clear_priv_key(rsa_key);
  clear_pub_key(rsa_key);
  
  G_OBJECT_CLASS(mega_rsa_key_parent_class)->finalize(object);
}

static void mega_rsa_key_class_init(MegaRsaKeyClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_rsa_key_set_property;
  gobject_class->get_property = mega_rsa_key_get_property;

  gobject_class->dispose = mega_rsa_key_dispose;
  gobject_class->finalize = mega_rsa_key_finalize;

  g_type_class_add_private(klass, sizeof(MegaRsaKeyPrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
