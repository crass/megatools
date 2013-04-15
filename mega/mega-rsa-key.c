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
#include <nettle/rsa.h>

struct _MegaRsaKeyPrivate
{
  // priv
  gboolean privk_loaded;
  mpz_t p;
  mpz_t q;
  mpz_t d;
  mpz_t u; // p^-1 mod q

  // pub
  gboolean pubk_loaded;
  mpz_t m;
  mpz_t e;
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

static void write_mpi(GString* buf, mpz_t n)
{
  g_return_if_fail(buf != NULL);
  g_return_if_fail(n != NULL);

  gsize size_bits = mpz_sizeinbase(n, 2);
  gsize size = (size_bits + 7) / 8;
  gsize off = buf->len;

  g_string_set_size(buf, buf->len + size + MPI_HDRSIZE);

  MPI_SET_BITS(buf->str + off, size_bits);
  mpz_export(buf->str + off + MPI_HDRSIZE, NULL, 1, 1, 1, 0, n);
}

static gboolean read_mpi(const guchar* buf, const guchar* end, const guchar** next, mpz_t n)
{
  gsize size;

  g_return_val_if_fail(buf != NULL, FALSE);
  g_return_val_if_fail(end != NULL, FALSE);
  g_return_val_if_fail(n != NULL, FALSE);

  if (end - buf < 2)
    return FALSE;

  size = MPI_SIZE(buf);
  if (end - buf < size)
    return FALSE;

  mpz_import(n, MPI_BYTES(buf), 1, 1, 1, 0, buf + MPI_HDRSIZE);

  if (next)
    *next = buf + size;

  return TRUE;
}

static void decrypt_rsa(mpz_t r, mpz_t m, mpz_t d, mpz_t p, mpz_t q, mpz_t u)
{
  mpz_t xp, mod_mp, mod_dp1, p1, xq, mod_mq, mod_dq1, q1, t;

  g_return_if_fail(r != NULL);
  g_return_if_fail(m != NULL);
  g_return_if_fail(d != NULL);
  g_return_if_fail(p != NULL);
  g_return_if_fail(q != NULL);
  g_return_if_fail(u != NULL);

  mpz_inits(xp, mod_mp, mod_dp1, p1, xq, mod_mq, mod_dq1, q1, t, NULL);

  // var xp = bmodexp(bmod(m,p), bmod(d,bsub(p,[1])), p);
  mpz_mod(mod_mp, m, p);
  mpz_sub_ui(p1, p, 1);
  mpz_mod(mod_dp1, d, p1);
  mpz_powm(xp, mod_mp, mod_dp1, p);

  // var xq = bmodexp(bmod(m,q), bmod(d,bsub(q,[1])), q);
  mpz_mod(mod_mq, m, q);
  mpz_sub_ui(q1, q, 1);
  mpz_mod(mod_dq1, d, q1);
  mpz_powm(xq, mod_mq, mod_dq1, q);

  // var t = bsub(xq,xp);
  if (mpz_cmp(xq, xp) <= 0)
  {
    mpz_sub(t, xp, xq);
    mpz_mul(r, t, u);
    mpz_mod(t, r, q);
    mpz_sub(t, q, t);
  }
  else
  {
    mpz_sub(t, xq, xp);
    mpz_mul(r, t, u);
    mpz_mod(t, r, q);
  }

  mpz_mul(r, t, p);
  mpz_add(r, r, xp);

  mpz_clears(xp, mod_mp, mod_dp1, p1, xq, mod_mq, mod_dq1, q1, t, NULL);
}

static void encrypt_rsa(mpz_t r, mpz_t s, mpz_t e, mpz_t m)
{
  g_return_if_fail(r != NULL);
  g_return_if_fail(s != NULL);
  g_return_if_fail(e != NULL);
  g_return_if_fail(m != NULL);

  mpz_powm(r, s, e, m);
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
  mpz_t c, m;
  guchar* message;
  gsize message_length;
  GString* cipher_mpi;
  gchar* str;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);
  g_return_val_if_fail(rsa_key->priv->pubk_loaded, NULL);

  message_length = (mpz_sizeinbase(rsa_key->priv->m, 2) >> 3) - 1;

  // check that data fits the message
  g_return_val_if_fail(len <= message_length, NULL);

  // create random padded message from data
  message = g_malloc0(message_length);
  memcpy(message, data, len);
  mega_randomness(message + len, message_length - len);
  mpz_init(m);
  mpz_import(m, message_length, 1, 1, 1, 0, message);
  g_free(message);

  // encrypt mesasge
  mpz_init(c);
  encrypt_rsa(c, m, rsa_key->priv->e, rsa_key->priv->m);
  mpz_clear(m);

  // encode result as MPI
  cipher_mpi = g_string_sized_new(256);
  write_mpi(cipher_mpi, c);
  mpz_clear(c);

  // right align 
  str = mega_base64urlencode(cipher_mpi->str, cipher_mpi->len);
  g_string_free(cipher_mpi, TRUE);
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
  MegaRsaKeyPrivate* priv;
  gsize cipherlen = 0;
  guchar* cipher_raw;
  guchar* data;
  gssize message_length;
  gsize m_size_bits, m_size;
  mpz_t c, m;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(cipher != NULL, NULL);
  g_return_val_if_fail(rsa_key->priv->privk_loaded, NULL);

  priv = rsa_key->priv;

  if (priv->pubk_loaded)
    message_length = (mpz_sizeinbase(priv->m, 2) >> 3) - 1;
  else
    message_length = -1;

  cipher_raw = mega_base64urldecode(cipher, &cipherlen);
  if (cipher_raw == NULL)
    return NULL;

  mpz_init(c);
  if (!read_mpi(cipher_raw, cipher_raw + cipherlen, NULL, c))
  {
    g_free(cipher_raw);
    return NULL;
  }

  g_free(cipher_raw);

  mpz_init(m);
  decrypt_rsa(m, c, priv->d, priv->p, priv->q, priv->u);
  mpz_clear(c);

  m_size_bits = mpz_sizeinbase(m, 2);
  m_size = (m_size_bits + 7) / 8;

  if (message_length < 0)
    message_length = m_size;

  // message doesn't fit message length of the original
  if (message_length < m_size)
  {
    mpz_clear(m);
    return NULL;
  }

  data = g_malloc0(message_length);

  // align decoded data to the right side of the message buffer (Mega doesn't do
  // this)
  mpz_export(data + (message_length - m_size), NULL, 1, 1, 1, 0, m);
  mpz_clear(m);

  return g_bytes_new_take(data, message_length);
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
  MegaRsaKeyPrivate* priv;
  gsize data_len = 0;
  const guchar *start, *end;
  GBytes* bytes;
  gboolean success;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);
  g_return_val_if_fail(privk != NULL, FALSE);
  g_return_val_if_fail(MEGA_IS_AES_KEY(enc_key), FALSE);

  priv = rsa_key->priv;

  bytes = mega_aes_key_decrypt(enc_key, privk);
  if (!bytes)
    return FALSE;

  start = g_bytes_get_data(bytes, &data_len);;
  end = start + data_len;

  success = 
         read_mpi(start, end, &start, priv->p)
      && read_mpi(start, end, &start, priv->q)
      && read_mpi(start, end, &start, priv->d)
      && read_mpi(start, end, &start, priv->u);

  priv->privk_loaded = success;

  g_bytes_unref(bytes);
  return success;
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
  MegaRsaKeyPrivate* priv;
  gsize data_len = 0;
  guchar *data;
  const guchar *start, *end;
  gboolean success;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);
  g_return_val_if_fail(pubk != NULL, FALSE);

  priv = rsa_key->priv;

  data = mega_base64urldecode(pubk, &data_len);
  if (data == NULL)
    return FALSE;

  start = data;
  end = start + data_len;

  success = 
       read_mpi(start, end, &start, priv->m)
    && read_mpi(start, end, &start, priv->e);

  priv->pubk_loaded = success;

  g_free(data);
  return success;
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
  MegaRsaKeyPrivate* priv;
  GString* data;
  gchar* str;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);

  priv = rsa_key->priv;

  data = g_string_sized_new(128 * 3);

  write_mpi(data, priv->m);
  write_mpi(data, priv->e);

  str = mega_base64urlencode(data->str, data->len);
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
  MegaRsaKeyPrivate* priv;
  GString* data;
  gchar* str;
  gsize off, pad;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), NULL);
  g_return_val_if_fail(MEGA_IS_AES_KEY(enc_key), NULL);

  priv = rsa_key->priv;
  data = g_string_sized_new(128 * 7);

  write_mpi(data, priv->p);
  write_mpi(data, priv->q);
  write_mpi(data, priv->d);
  write_mpi(data, priv->u);

  // add random padding
  off = data->len;
  pad = data->len % 16 ? 16 - (data->len % 16) : 0;
  if (pad)
  {
    g_string_set_size(data, data->len + pad);
    mega_randomness(data->str + off, pad);
  }

  str = mega_aes_key_encrypt(enc_key, data->str, data->len);
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
  MegaRsaKeyPrivate* priv;
  struct rsa_public_key pubk;
  struct rsa_private_key privk;

  g_return_val_if_fail(MEGA_IS_RSA_KEY(rsa_key), FALSE);

  priv = rsa_key->priv;
  rsa_private_key_init(&privk);
  rsa_public_key_init(&pubk);

  mpz_set_ui(pubk.e, 3);

  gboolean success = rsa_generate_keypair(&pubk, &privk, NULL, mega_randomness_nettle, NULL, NULL, 2048, 0);
  if (!success)
  {
    rsa_private_key_clear(&privk);
    rsa_public_key_clear(&pubk);
    return FALSE;
  }

  mpz_set(priv->p, privk.q);
  mpz_set(priv->q, privk.p);
  mpz_set(priv->d, privk.d);
  mpz_set(priv->u, privk.c);

  mpz_set(priv->m, pubk.n);
  mpz_set(priv->e, pubk.e);

  rsa_private_key_clear(&privk);
  rsa_public_key_clear(&pubk);

  priv->pubk_loaded = TRUE;
  priv->privk_loaded = TRUE;

  return TRUE;
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

  MegaRsaKeyPrivate* priv = rsa_key->priv;

  mpz_inits(priv->p, priv->q, priv->d, priv->u, priv->m, priv->e, NULL);
}

static void mega_rsa_key_dispose(GObject *object)
{
  MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);

  //
  // Free everything that may hold reference to MegaRsaKey
  //

  G_OBJECT_CLASS(mega_rsa_key_parent_class)->dispose(object);
}

static void mega_rsa_key_finalize(GObject *object)
{
  MegaRsaKey *rsa_key = MEGA_RSA_KEY(object);
  MegaRsaKeyPrivate* priv = rsa_key->priv;

  mpz_clears(priv->p, priv->q, priv->d, priv->u, priv->m, priv->e, NULL);

  //rsa_private_key_clear(&rsa_key->priv->priv);
  //rsa_public_key_clear(&rsa_key->priv->pub);
  
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
