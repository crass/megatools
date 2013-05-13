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

#include "oldmega.h"
#include "http.h"
#include "sjson.h"
#include "mega/mega.h"

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define CACHE_FORMAT_VERSION 3

gint mega_debug = 0;

// Data structures and enums

// {{{ SRV_E*

enum 
{
  SRV_EINTERNAL = -1,
  SRV_EARGS = -2,
  SRV_EAGAIN = -3,
  SRV_ERATELIMIT = -4,
  SRV_EFAILED = -5,
  SRV_ETOOMANY = -6,
  SRV_ERANGE = -7,
  SRV_EEXPIRED = -8,

  // FS access errors
  SRV_ENOENT = -9,
  SRV_ECIRCULAR = -10,
  SRV_EACCESS = -11,
  SRV_EEXIST = -12,
  SRV_EINCOMPLETE = -13,

  // crypto errors
  SRV_EKEY = -14,

  // user errors
  SRV_ESID = -15,
  SRV_EBLOCKED = -16,
  SRV_EOVERQUOTA = -17,
  SRV_ETEMPUNAVAIL = -18,
  SRV_ETOOMANYCONNECTIONS = -19
};

// }}}
// {{{ rsa_key

typedef struct _rsa_key rsa_key;

struct _rsa_key {
  // priv
  BIGNUM* p;
  BIGNUM* q;
  BIGNUM* d;
  BIGNUM* u; // p^-1 mod q
  // pub
  BIGNUM* m;
  BIGNUM* e;
};

// }}}
// {{{ mega_session

struct _mega_sesssion 
{
  MegaHttpClient* http;

  gint id;
  gchar* sid;
  gchar* sid_param_name;
  gchar* rid;

  guchar* password_key;
  guchar* master_key;
  rsa_key rsa_key;

  gchar* user_handle;
  gchar* user_name;
  gchar* user_email;

  GHashTable* share_keys;

  GSList* fs_nodes;
  GHashTable* fs_pathmap;

  // progress reporting
  mega_status_callback status_callback;
  mega_status_data status_data;
  gpointer status_userdata;

  gint64 last_refresh;
};

// }}}

// JSON helpers

// {{{ print_node

static void print_node(const gchar* n, const gchar* prefix)
{
  gchar* pretty = s_json_pretty(n);
  g_print("%s%s\n", prefix, pretty);
  g_free(pretty);
}

// }}}
// {{{ s_json_get_member_bytes

static guchar* s_json_get_member_bytes(const gchar* node, const gchar* name, gsize* out_len)
{
  g_return_val_if_fail(node != NULL, NULL);
  g_return_val_if_fail(name != NULL, NULL);
  g_return_val_if_fail(out_len != NULL, NULL);

  gchar* data = s_json_get_member_string(node, name);
  if (data)
  {
    gchar* b64 = g_base64_decode(data, out_len);
    g_free(data);
    return b64;
  }

  return NULL;
}

// }}}
// {{{ s_json_get_member_bn

static BIGNUM* s_json_get_member_bn(const gchar* node, const gchar* name)
{
  g_return_val_if_fail(node != NULL, NULL);
  g_return_val_if_fail(name != NULL, NULL);

  gchar* data = s_json_get_member_string(node, name);
  if (data)
  {
    BIGNUM* n = NULL;
    if (BN_dec2bn(&n, data))
    {
      g_free(data);
      return n;
    }

    g_free(data);
  }

  return NULL;
}

void s_json_get_member_rsa_key(const gchar* node, const gchar* name, rsa_key* key)
{
  g_return_if_fail(node != NULL);
  g_return_if_fail(name != NULL);
  g_return_if_fail(key != NULL);

  const gchar* member = s_json_get_member(node, name);
  if (!member || s_json_get_type(member) != S_JSON_TYPE_OBJECT)
    return;

#define READ_COMPONENT(c) \
  key->c = s_json_get_member_bn(member, #c)

  READ_COMPONENT(p);
  READ_COMPONENT(q);
  READ_COMPONENT(d);
  READ_COMPONENT(u);
  READ_COMPONENT(m);
  READ_COMPONENT(e);

#undef READ_COMPONENT
}

// }}}
// {{{ s_json_gen_member_bytes

static void s_json_gen_member_bytes(SJsonGen* gen, const gchar* name, guchar* data, gsize len)
{
  if (data)
  {
    gchar* tmp = g_base64_encode(data, len);
    s_json_gen_member_string(gen, name, tmp);
    g_free(tmp);
  }
  else
  {
    s_json_gen_member_null(gen, name);
  }
}

// }}}
// {{{ s_json_gen_member_rsa_key

static void s_json_gen_member_bn(SJsonGen* gen, const gchar* name, BIGNUM* n)
{
  gchar* tmp = BN_bn2dec(n);
  s_json_gen_member_string(gen, name, tmp);
  OPENSSL_free(tmp);
}

static void s_json_gen_member_rsa_key(SJsonGen* gen, const gchar* name, rsa_key* key)
{
  s_json_gen_member_object(gen, name);

#define ADD_COMPONENT(name) \
  if (key->name) \
    s_json_gen_member_bn(gen, #name, key->name);

  ADD_COMPONENT(p)
  ADD_COMPONENT(q)
  ADD_COMPONENT(d)
  ADD_COMPONENT(u)
  ADD_COMPONENT(m)
  ADD_COMPONENT(e)

#undef ADD_COMPONENT

  s_json_gen_end_object(gen);
}

// }}}

// Crypto utilities

#define DW(p, n) (*((guint32*)(p) + (n)))

// {{{ multi-precision integer macros

#define MPI_BITS(ptr) GUINT16_FROM_BE(*(guint16*)(ptr))
#define MPI_BYTES(ptr) ((MPI_BITS(ptr) + 7) / 8)
#define MPI_SIZE(ptr) (MPI_BYTES(ptr) + MPI_HDRSIZE)
#define MPI_HDRSIZE 2
#define MPI2BN(ptr) \
  BN_bin2bn((ptr) + MPI_HDRSIZE, MPI_BYTES(ptr), NULL)

// }}}
// {{{ base64urlencode

static gchar* base64urlencode(const guchar* data, gsize len)
{
  gint i, shl;
  gchar *sh, *she, *p;

  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);

  sh = g_base64_encode(data, len);
  shl = strlen(sh);

  she = g_malloc0(shl + 1), p = she;
  for (i = 0; i < shl; i++)
  {
    if (sh[i] == '+')
      *p = '-';
    else if (sh[i] == '/')
      *p = '_';
    else if (sh[i] == '=')
      continue;
    else
      *p = sh[i];
    p++;
  }

  *p = '\0';

  g_free(sh);
  return she;
}

// }}}
// {{{ base64urldecode

static guchar* base64urldecode(const gchar* str, gsize* len)
{
  GString* s;
  gint i;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(len != NULL, NULL);

  s = g_string_new(str);

  for (i = 0; i < s->len; i++)
  {
    if (s->str[i] == '-')
      s->str[i] = '+';
    else if (s->str[i] == '_')
      s->str[i] = '/';
  }

  gint eqs = (s->len * 3) & 0x03;
  for (i = 0; i < eqs; i++)
    g_string_append_c(s, '=');

  guchar* data = g_base64_decode(s->str, len);

  g_string_free(s, TRUE);

  return data;
}

// }}}
// {{{ aes128_decrypt

G_GNUC_UNUSED static gboolean aes128_decrypt(guchar* out, const guchar* in, gsize len, const guchar* key)
{
  AES_KEY k;
  gsize off;

  g_return_val_if_fail(out != NULL, FALSE);
  g_return_val_if_fail(in != NULL, FALSE);
  g_return_val_if_fail(len % 16 == 0, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);

  AES_set_decrypt_key(key, 128, &k);

  for (off = 0; off < len; off += 16)
    AES_decrypt(in + off, out + off, &k);

  return TRUE;
}

// }}}
// {{{ aes128_encrypt

static gboolean aes128_encrypt(guchar* out, const guchar* in, gsize len, const guchar* key)
{
  AES_KEY k;
  gsize off;

  g_return_val_if_fail(out != NULL, FALSE);
  g_return_val_if_fail(in != NULL, FALSE);
  g_return_val_if_fail(len % 16 == 0, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);

  AES_set_encrypt_key(key, 128, &k);

  for (off = 0; off < len; off += 16)
    AES_encrypt(in + off, out + off, &k);

  return TRUE;
}

// }}}
// {{{ b64_aes128_decrypt

static guchar* b64_aes128_decrypt(const gchar* str, const guchar* key, gsize* outlen)
{
  AES_KEY k;
  gsize cipherlen = 0;
  gsize off;
  guchar* cipher;
  guchar* data;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  AES_set_decrypt_key(key, 128, &k);

  cipher = base64urldecode(str, &cipherlen);
  if (cipher == NULL)
    return NULL;

  if (cipherlen % 16 != 0)
  {
    g_free(cipher);
    return NULL;
  }

  data = g_malloc0(cipherlen);
  for (off = 0; off < cipherlen; off += 16)
    AES_decrypt(cipher + off, data + off, &k);

  g_free(cipher);

  if (outlen)
    *outlen = cipherlen;

  return data;
}

// }}}
// {{{ b64_aes128_encrypt

static gchar* b64_aes128_encrypt(const guchar* data, gsize len, const guchar* key)
{
  AES_KEY k;
  gsize off;
  guchar* cipher;
  gchar* str;

  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail((len % 16) == 0, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  AES_set_encrypt_key(key, 128, &k);

  cipher = g_malloc0(len);
  for (off = 0; off < len; off += 16)
    AES_encrypt(data + off, cipher + off, &k);

  str = base64urlencode(cipher, len);

  g_free(cipher);

  return str;
}

// }}}
// {{{ b64_aes128_cbc_decrypt

static guchar* b64_aes128_cbc_decrypt(const gchar* str, const guchar* key, gsize* outlen)
{
  AES_KEY k;
  gsize cipherlen = 0;
  guchar* cipher;
  guchar* data;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  AES_set_decrypt_key(key, 128, &k);

  cipher = base64urldecode(str, &cipherlen);
  if (cipher == NULL)
    return NULL;

  if (cipherlen % 16 != 0)
  {
    g_free(cipher);
    return NULL;
  }

  data = g_malloc0(cipherlen + 1);
  guchar iv[AES_BLOCK_SIZE] = {0};
  AES_cbc_encrypt(cipher, data, cipherlen, &k, iv, 0);

  g_free(cipher);

  if (outlen)
    *outlen = cipherlen;

  return data;
}

// }}}
// {{{ b64_aes128_cbc_encrypt

static gchar* b64_aes128_cbc_encrypt(const guchar* data, gsize len, const guchar* key)
{
  AES_KEY k;
  guchar* cipher;
  gchar* str;
  guchar iv[AES_BLOCK_SIZE] = {0};

  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail((len % 16) == 0, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  AES_set_encrypt_key(key, 128, &k);

  cipher = g_malloc0(len);
  AES_cbc_encrypt(data, cipher, len, &k, iv, 1);
  str = base64urlencode(cipher, len);
  g_free(cipher);

  return str;
}

// }}}
// {{{ b64_aes128_cbc_encrypt_str

static gchar* b64_aes128_cbc_encrypt_str(const gchar* str, const guchar* key)
{
  gsize len = 0;
  guchar* data;
  gchar* out;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  len = strlen(str) + 1;
  if (len % 16)
    len += 16 - (len % 16);

  data = g_malloc0(len);
  memcpy(data, str, len - 1);
  out = b64_aes128_cbc_encrypt(data, len, key);
  g_free(data);

  return out;
}

// }}}
// {{{ b64_aes128_decrypt_privk

static gboolean b64_aes128_decrypt_privk(const gchar* str, const guchar* key, rsa_key* rsa)
{
  gsize data_len = 0;
  guchar *data, *p, *e;

  g_return_val_if_fail(str != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(rsa != NULL, FALSE);

  data = b64_aes128_decrypt(str, key, &data_len);
  if (!data)
    return FALSE;

  p = data;
  e = p + data_len;

  if (p + MPI_SIZE(p) > e)
    goto bounds;
  
  rsa->p = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  rsa->q = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  rsa->d = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  rsa->u = MPI2BN(p);

  g_free(data);
  return TRUE;

bounds:
  g_free(data);
  return FALSE;
}

// }}}
// {{{ b64_decode_pubk

static gboolean b64_decode_pubk(const gchar* str, rsa_key* rsa)
{
  gsize data_len = 0;
  guchar *data, *p, *e;

  g_return_val_if_fail(str != NULL, FALSE);
  g_return_val_if_fail(rsa != NULL, FALSE);

  data = base64urldecode(str, &data_len);
  if (data == NULL)
    return FALSE;

  p = data;
  e = p + data_len;

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  rsa->m = MPI2BN(p); p += MPI_SIZE(p);

  if (p + MPI_SIZE(p) > e)
    goto bounds;

  rsa->e = MPI2BN(p);

  g_free(data);
  return TRUE;

bounds:
  g_free(data);
  return FALSE;
}

// }}}
// {{{ b64_aes128_encrypt_privk

static void append_mpi_from_bn(GString* buf, BIGNUM* n)
{
  g_return_if_fail(buf != NULL);
  g_return_if_fail(n != NULL);

  gsize size = BN_num_bytes(n);
  gsize off = buf->len;

  g_string_set_size(buf, buf->len + size + MPI_HDRSIZE);

  *(guint16*)(buf->str + off) = GUINT16_TO_BE(BN_num_bits(n));
  
  BN_bn2bin(n, buf->str + off + MPI_HDRSIZE);
}

static gchar* b64_aes128_encrypt_privk(const guchar* key, rsa_key* rsa)
{
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(rsa != NULL, FALSE);

  GString* data = g_string_sized_new(128 * 7);

  append_mpi_from_bn(data, rsa->p);
  append_mpi_from_bn(data, rsa->q);
  append_mpi_from_bn(data, rsa->d);
  append_mpi_from_bn(data, rsa->u);

  gsize off = data->len;
  gsize pad = data->len % 16 ? 16 - (data->len % 16) : 0;
  if (pad)
  {
    g_string_set_size(data, data->len + pad);
    while (off < data->len)
      data->str[off++] = 0;
  }

  gchar* str = b64_aes128_encrypt(data->str, data->len, key);

  g_string_free(data, TRUE);

  return str;
}

// }}}
// {{{ b64_encode_pubk

static gchar* b64_encode_pubk(rsa_key* rsa)
{
  g_return_val_if_fail(rsa != NULL, FALSE);

  GString* data = g_string_sized_new(128 * 3);

  append_mpi_from_bn(data, rsa->m);
  append_mpi_from_bn(data, rsa->e);

  gchar* str = base64urlencode(data->str, data->len);

  g_string_free(data, TRUE);

  return str;
}

// }}}
// {{{ rsa_decrypt

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

// }}}
// {{{ rsa_encrypt

/*
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
*/

// }}}
// {{{ b64_rsa_decrypt

static guchar* b64_rsa_decrypt(const gchar* str, rsa_key* key, gsize* outlen)
{
  gsize cipherlen = 0;
  guchar* cipher;
  guchar* data;
  BIGNUM *c, *m;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  cipher = base64urldecode(str, &cipherlen);
  if (cipher == NULL)
    return NULL;

  if (MPI_SIZE(cipher) > cipherlen)
  {
    g_free(cipher);
    return NULL;
  }

  c = MPI2BN(cipher);
  g_free(cipher);

  m = rsa_decrypt(c, key->d, key->p, key->q, key->u);
  BN_free(c);

  if (!m) 
    return NULL;

  data = g_malloc0(BN_num_bytes(m) + 1);
  BN_bn2bin(m, data);

  if (outlen)
    *outlen = BN_num_bytes(m);

  BN_free(m);

  return data;
}

// }}}
// {{{ rsa_key_gen

static gboolean rsa_key_gen(rsa_key* k)
{
  RSA* key;

  g_return_val_if_fail(k != NULL, FALSE);
  g_return_val_if_fail(k->p == NULL, FALSE);
  g_return_val_if_fail(k->m == NULL, FALSE);

  key = RSA_generate_key(2048, RSA_3, NULL, NULL);
  if (!key)
    return FALSE;

  if (RSA_check_key(key) != 1)
  {
    RSA_free(key);
    return FALSE;
  }

  // private part
  k->p = BN_dup(key->q);
  k->q = BN_dup(key->p);
  k->d = BN_dup(key->d);
  k->u = BN_dup(key->iqmp);

  // public part
  k->m = BN_dup(key->n);
  k->e = BN_dup(key->e);

  RSA_free(key);

  return TRUE;
}

// }}}
// {{{ rsa_key_free

static void rsa_key_free(rsa_key* k)
{
  if (!k)
    return;

  if (k->p) BN_free(k->p);
  if (k->q) BN_free(k->q);
  if (k->d) BN_free(k->d);
  if (k->u) BN_free(k->u);
  if (k->m) BN_free(k->m);
  if (k->e) BN_free(k->e);

  memset(k, 0, sizeof(rsa_key));
}

// }}}
// {{{ make_random_key

static guchar* make_random_key(void)
{
  guchar k[16];

  //XXX: error check
  RAND_bytes(k, sizeof(k));

  return g_memdup(k, 16);
}

// }}}
// {{{ make_password_key

static guchar* make_password_key(const gchar* password)
{
  guchar pkey[16] = {0x93, 0xC4, 0x67, 0xE3, 0x7D, 0xB0, 0xC7, 0xA4, 0xD1, 0xBE, 0x3F, 0x81, 0x01, 0x52, 0xCB, 0x56};
  gint i, r;
  gint len;

  g_return_val_if_fail(password != NULL, NULL);

  len = strlen(password);

  for (r = 65536; r--; )
  {
    for (i = 0; i < len; i += 16)
    {
      AES_KEY k;
      guchar key[16] = {0}, pkey_tmp[16];
      strncpy(key, password + i, 16);

      AES_set_encrypt_key(key, 128, &k);
      AES_encrypt(pkey, pkey_tmp, &k);  
      memcpy(pkey, pkey_tmp, 16);
    }
  }

  return g_memdup(pkey, 16);
}

// }}}
// {{{ make_username_hash

static gchar* make_username_hash(const gchar* un, const guchar* key)
{
  AES_KEY k;
  gint l, i;
  guchar hash[16] = {0}, hash_tmp[16], oh[8];

  g_return_val_if_fail(un != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);

  AES_set_encrypt_key(key, 128, &k);

  for (i = 0, l = strlen(un); i < l; i++) 
    hash[i % 16] ^= un[i];

  for (i = 16384; i--; ) 
  {
    AES_encrypt(hash, hash_tmp, &k);  
    memcpy(hash, hash_tmp, 16);
  }

  memcpy(oh, hash, 4);
  memcpy(oh + 4, hash + 8, 4);

  return base64urlencode(oh, 8);
}

// }}}
// {{{ make_request_id

static guchar* make_request_id(void)
{
  const gchar chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  gchar k[11] = {0};
  gint i;

  for (i = 0; i < 10; i++)
    k[i] = chars[rand() % sizeof(chars)];

  return g_strdup(k);
}

// }}}
// {{{ chunked CBC-MAC

static guint64 get_chunk_size(gsize idx)
{
  return (idx < 8 ? idx + 1 : 8) * 1024 * 128;
}

/*
static gsize get_chunk_off(gint idx)
{
  gsize p = 0;
  gint i = 0;

  for (i = 0; i < idx; i++)
    p += get_chunk_size(i);

  return p;
}
*/

typedef struct 
{
  AES_KEY k;
  gsize chunk_idx;
  guint64 next_boundary;
  guint64 position;
  guchar chunk_mac_iv[16];
  guchar chunk_mac[16];
  guchar meta_mac[16];
} chunked_cbc_mac;

static void chunked_cbc_mac_init(chunked_cbc_mac* mac, guchar key[16], guchar iv[16])
{
  g_return_if_fail(mac != NULL);
  g_return_if_fail(key != NULL);

  memset(mac, 0, sizeof(*mac));
  memcpy(mac->chunk_mac_iv, iv, 16);
  memcpy(mac->chunk_mac, mac->chunk_mac_iv, 16);
  AES_set_encrypt_key(key, 128, &mac->k);
  mac->next_boundary = get_chunk_size(mac->chunk_idx);
}

static void chunked_cbc_mac_init8(chunked_cbc_mac* mac, guchar key[16], guchar iv[8])
{
  g_return_if_fail(iv != NULL);

  guchar mac_iv[16];
  memcpy(mac_iv, iv, 8);
  memcpy(mac_iv + 8, iv, 8);

  chunked_cbc_mac_init(mac, key, mac_iv);
}

static void chunked_cbc_mac_close_chunk(chunked_cbc_mac* mac)
{
  gint i;
  guchar tmp[16];

  for (i = 0; i < 16; i++)
    mac->meta_mac[i] ^= mac->chunk_mac[i];

  AES_encrypt(mac->meta_mac, tmp, &mac->k);
  memcpy(mac->meta_mac, tmp, 16);

  memcpy(mac->chunk_mac, mac->chunk_mac_iv, 16);
  mac->next_boundary += get_chunk_size(++mac->chunk_idx);
}

static void chunked_cbc_mac_update(chunked_cbc_mac* mac, const guchar* data, gsize len)
{
  gsize i;

  g_return_if_fail(mac != NULL);
  g_return_if_fail(data != NULL);

  for (i = 0; i < len; i++)
  {
    mac->chunk_mac[mac->position % 16] ^= data[i];
    mac->position++;

    if (G_UNLIKELY((mac->position % 16) == 0))
    {
      guchar tmp[16];
      AES_encrypt(mac->chunk_mac, tmp, &mac->k);
      memcpy(mac->chunk_mac, tmp, 16);
    }

    // add chunk mac to the chunk macs list if we are at the chunk boundary
    if (G_UNLIKELY(mac->position == mac->next_boundary)) 
      chunked_cbc_mac_close_chunk(mac);
  }
}

static void chunked_cbc_mac_finish(chunked_cbc_mac* mac, guchar mac_out[16])
{
  g_return_if_fail(mac != NULL);

  // finish buffer if necessary
  if (mac->position % 16)
  {
    while (mac->position % 16)
    {
      mac->chunk_mac[mac->position % 16] ^= 0;
      mac->position++;
    }

    guchar tmp[16];
    AES_encrypt(mac->chunk_mac, tmp, &mac->k);
    memcpy(mac->chunk_mac, tmp, 16);
  }

  // if there last chunk is unfinished, finish it
  if (mac->position > (mac->next_boundary - get_chunk_size(mac->chunk_idx)))
    chunked_cbc_mac_close_chunk(mac);

  if (mac_out)
    memcpy(mac_out, mac->meta_mac, 16);

  memset(mac, 0, sizeof(*mac));
}

static void chunked_cbc_mac_finish8(chunked_cbc_mac* mac, guchar mac_out[8])
{
  guchar buf[16];
  gint i;

  g_return_if_fail(mac_out != NULL);

  chunked_cbc_mac_finish(mac, buf);

  for (i = 0; i < 4; i++)
    mac_out[i] = buf[i] ^ buf[i + 4];
  for (i = 0; i < 4; i++)
    mac_out[i + 4] = buf[i + 8] ^ buf[i + 12];
}

// }}}
// {{{ unpack_node_key

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

// }}}
// {{{ pack_node_key

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

// }}}
// {{{ encode_node_attrs

static gchar* encode_node_attrs(const gchar* name)
{
  g_return_val_if_fail(name != NULL, NULL);

  SJsonGen* gen = s_json_gen_new();
  s_json_gen_start_object(gen);
  s_json_gen_member_string(gen, "n", name);
  s_json_gen_end_object(gen);
  gchar* attrs_json = s_json_gen_done(gen);
  gchar* attrs = g_strdup_printf("MEGA%s", attrs_json);
  g_free(attrs_json);

  return attrs;
}

// }}}
// {{{ decode_node_attrs

static gboolean decode_node_attrs(const gchar* attrs, gchar** name)
{
  g_return_val_if_fail(attrs != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  // parse attributes
  if (!attrs || !g_str_has_prefix(attrs, "MEGA{"))
    return FALSE;

  // decode JSON
  if (!s_json_is_valid(attrs + 4))
    return FALSE;

  *name = s_json_get_member_string(attrs + 4, "n");

  return TRUE;
}

// }}}
// {{{ decrypt_node_attrs

static gboolean decrypt_node_attrs(const gchar* encrypted_attrs, const guchar* key, gchar** name)
{
  g_return_val_if_fail(encrypted_attrs != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  guchar* attrs = b64_aes128_cbc_decrypt(encrypted_attrs, key, NULL);
  gboolean status = decode_node_attrs(attrs, name);
  g_free(attrs);

  return status;
}

// }}}
// {{{ handle_auth

gboolean handle_auth(const gchar* handle, const gchar* b64_ha, const guchar* master_key)
{
  gsize ha_len = 0;
  gboolean status;

  g_return_val_if_fail(handle != NULL, FALSE);
  g_return_val_if_fail(b64_ha != NULL, FALSE);
  g_return_val_if_fail(master_key != NULL, FALSE);

  guchar* ha = b64_aes128_decrypt(b64_ha, master_key, &ha_len);
  if (!ha || ha_len != 16)
  {
    g_free(ha);
    return FALSE;
  }

  status = !memcmp(ha, handle, 8) && !memcmp(ha + 8, handle, 8);

  g_free(ha);

  return status;
}

// }}}

// Server API helpers

// {{{ srv_error_to_string

static const gchar* srv_error_to_string(gint code)
{
  switch (code) 
  {
    case SRV_EINTERNAL           : return "EINTERNAL";
    case SRV_EARGS               : return "EARGS";
    case SRV_EAGAIN              : return "EAGAIN";
    case SRV_ERATELIMIT          : return "ERATELIMIT";
    case SRV_EFAILED             : return "EFAILED";
    case SRV_ETOOMANY            : return "ETOOMANY";
    case SRV_ERANGE              : return "ERANGE";
    case SRV_EEXPIRED            : return "EEXPIRED";
    case SRV_ENOENT              : return "ENOENT";
    case SRV_ECIRCULAR           : return "ECIRCULAR";
    case SRV_EACCESS             : return "EACCESS";
    case SRV_EEXIST              : return "EEXIST";
    case SRV_EINCOMPLETE         : return "EINCOMPLETE";
    case SRV_EKEY                : return "EKEY";
    case SRV_ESID                : return "ESID";
    case SRV_EBLOCKED            : return "EBLOCKED";
    case SRV_EOVERQUOTA          : return "EOVERQUOTA";
    case SRV_ETEMPUNAVAIL        : return "ETEMPUNAVAIL";
    case SRV_ETOOMANYCONNECTIONS : return "ETOOMANYCONNECTIONS";
    default                      : return "EUNKNOWN";
  }
}

// }}}

// {{{ api_request_unsafe

static gchar* api_request_unsafe(mega_session* s, const gchar* req_node, GError** err)
{
  GError* local_err = NULL;
  gchar* url = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(req_node != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  if (mega_debug & MEGA_DEBUG_API)
    print_node(req_node, "-> ");

  // prepare URL
  s->id++;
  if (s->sid)
    url = g_strdup_printf("https://eu.api.mega.co.nz/cs?id=%u&%s=%s", s->id, s->sid_param_name ? s->sid_param_name : "sid", s->sid);
  else
    url = g_strdup_printf("https://eu.api.mega.co.nz/cs?id=%u", s->id);

  GString* res_str = mega_http_client_post_simple(s->http, url, req_node, -1, &local_err);
  g_free(url);

  // handle http errors
  if (!res_str)
  {
    if (local_err->domain == MEGA_HTTP_CLIENT_ERROR && local_err->code == MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN)
    {
      // simulate SRV_EAGAIN response if server drops connection
      return g_strdup_printf("%d", SRV_EAGAIN);
    }
    else
    {
      g_propagate_prefixed_error(err, local_err, "HTTP POST failed: ");
      return NULL;
    }
  }

  // decode JSON
  if (!s_json_is_valid(res_str->str))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response JSON");
    g_string_free(res_str, TRUE);
    return NULL;
  }

  gchar* res_node = g_string_free(res_str, FALSE);

  if (mega_debug & MEGA_DEBUG_API && res_node)
    print_node(res_node, "<- ");

  return res_node;
}

// }}}
// {{{ api_request

static gchar* api_request(mega_session* s, const gchar* req_node, GError** err)
{
  GError* local_err = NULL;
  gchar* response;
  gint delay = 250000; // repeat after 250ms 500ms 1s ...

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(req_node != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  // some default rate limiting
  g_usleep(20000);

again:
  response = api_request_unsafe(s, req_node, &local_err);
  if (!response) 
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  // if we are asked to repeat the call, do it with exponential backoff
  if (s_json_get_type(response) == S_JSON_TYPE_NUMBER && s_json_get_int(response, SRV_EINTERNAL) == SRV_EAGAIN)
  {
    g_free(response);
    g_usleep(delay);
    delay = delay * 2;

    if (delay > 4 * 1000 * 1000)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server keeps asking us for EAGAIN, giving up");
      return NULL;
    }

    goto again;
  }

  return response;
}

// }}}
// {{{ api_response_check

// check that we have and array with a response value (object or error code)
static const gchar* api_response_check(const gchar* response, gchar expects, gint* error_code, GError** err)
{
  // there was already an error returned by api_request
  if (*err)
    return NULL;

  // null response without an error, it shouldn't happen, but handle it to be sure
  if (!response)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Null response");
    return NULL;
  }

  if (error_code)
    *error_code = 0;

  SJsonType response_type = s_json_get_type(response);

  // request level error
  if (response_type == S_JSON_TYPE_NUMBER)
  {
    gint v = s_json_get_int(response, 0);

    // if it's negative, it's error status
    if (v < 0)
    {
      if (error_code)
        *error_code = v;

      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error %s", srv_error_to_string(v));
      return NULL;
    }
  } 
  // check that we have and array with a response value
  else if (response_type == S_JSON_TYPE_ARRAY)
  {
    const gchar* node = s_json_get_element(response, 0);
    if (node)
    {
      SJsonType node_type = s_json_get_type(node);

      // we got object
      if (node_type == S_JSON_TYPE_OBJECT)
      {
        if (expects == 'o')
          return node;
      }
      else if (node_type == S_JSON_TYPE_ARRAY)
      {
        if (expects == 'a')
          return node;
      }
      else if (node_type == S_JSON_TYPE_NUMBER)
      {
        // we got int number
        gint v = s_json_get_int(node, 0);

        // if it's negative, it's error status
        if (v < 0)
        {
          if (error_code)
            *error_code = v;

          g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error %s", srv_error_to_string(v));
          return NULL;
        }
        
        if (expects == 'i')
          return node;
      }
      else if (node_type == S_JSON_TYPE_BOOL)
      {
        if (expects == 'b')
          return node;
      }
      else if (node_type == S_JSON_TYPE_STRING)
      {
        if (expects == 's')
          return node;
      }
      else if (node_type == S_JSON_TYPE_NULL)
      {
        if (expects == 'n')
          return node;
      }
    }
  }

  g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Unexpected response");
  return NULL;
}

// }}}
// {{{ api_call

static gchar* api_call(mega_session* s, gchar expects, gint* error_code, GError** err, const gchar* format, ...)
{
  gchar *request, *response, *node_copy;
  const gchar* node;
  va_list args;

  g_return_val_if_fail(err != NULL && *err == NULL, NULL);
  g_return_val_if_fail(format != NULL, NULL);

  va_start(args, format);
  request = s_json_buildv(format, args);
  va_end(args);

  if (request == NULL)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid request format: %s", format);
    return NULL;
  }

  response = api_request(s, request, err);

  node = api_response_check(response, expects, error_code, err);
  if (*err)
  {
    const gchar* method_node = s_json_path(request, "$[0].a!string");

    if (method_node)
    {
      gchar* method = s_json_get_string(method_node);
      g_prefix_error(err, "API call '%s' failed: ", method);
      g_free(method);
    }
    else
      g_prefix_error(err, "API call failed: ");

    g_free(request);
    g_free(response);
    return NULL;
  }

  node_copy = s_json_get(node);

  g_free(request);
  g_free(response);

  return node_copy;
}

// }}}

// Remote filesystem helpers

// {{{ build_pathmap

static void build_pathmap(mega_session* s, const gchar* parent_handle, const gchar* base_path);

static void build_su_pathmap(mega_session* s, const gchar* parent_handle, const gchar* base_path)
{
  GSList* i;

  for (i = s->fs_nodes; i; i = i->next)
  {
    mega_node* n = i->data;

    // for each node
    if ((n->su_handle && parent_handle && !strcmp(n->su_handle, parent_handle)))
    {
      gchar* path = g_strdup_printf("%s/%s", base_path, n->name);

      if (g_hash_table_lookup(s->fs_pathmap, path))
      {
        gchar* tmp = g_strconcat(path, ".", n->handle, NULL);
        g_free(path);
        path = tmp;

        g_printerr("WARNING: Dup node detected, will be accessible as %s\n", path);
      }

      g_hash_table_insert(s->fs_pathmap, path, n);

      build_pathmap(s, n->handle, path);

      g_free(n->path);
      n->path = g_strdup(path);
    }
  }
}

static void build_pathmap(mega_session* s, const gchar* parent_handle, const gchar* base_path)
{
  GSList* i;

  for (i = s->fs_nodes; i; i = i->next)
  {
    mega_node* n = i->data;

    // for each node
    if ((!n->parent_handle && !parent_handle) // root nodes
        || (n->parent_handle && parent_handle && !strcmp(n->parent_handle, parent_handle)))
    {
      gchar* path = g_strdup_printf("%s/%s", base_path, n->name);

      if (g_hash_table_lookup(s->fs_pathmap, path))
      {
        gchar* tmp = g_strconcat(path, ".", n->handle, NULL);
        g_free(path);
        path = tmp;

        g_printerr("WARNING: Dup node detected, will be accessible as %s\n", path);
      }

      g_hash_table_insert(s->fs_pathmap, path, n);

      if (n->type == MEGA_NODE_CONTACT) 
        build_su_pathmap(s, n->handle, path);
      else
        build_pathmap(s, n->handle, path);

      g_free(n->path);
      n->path = g_strdup(path);
    }
  }
}

// }}}
// {{{ update_pathmap

static void update_pathmap(mega_session* s)
{
  g_return_if_fail(s != NULL);

  if (!s->fs_pathmap)
    s->fs_pathmap = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  else
    g_hash_table_remove_all(s->fs_pathmap);

  build_pathmap(s, NULL, "");
}

// }}}
// {{{ path manipulation utils

static gchar* path_sanitize_slashes(const gchar* path)
{
  g_return_val_if_fail(path != NULL, NULL);

  gchar* sanepath = g_malloc(strlen(path) + 1);
  gchar* tmp = sanepath;
  gboolean previous_was_slash = 0;

  while (*path != '\0')
  {
    if (*path != '/' || !previous_was_slash)
      *(tmp++) = *path;

    previous_was_slash = *path == '/'?1:0;
    path++;
  }

  *tmp = '\0';
  if (tmp > (sanepath + 1) && *(tmp - 1) == '/')
    *(tmp-1) = '\0';

  return sanepath;
}

static gchar** path_get_elements(const gchar* path)
{
  g_return_val_if_fail(path != NULL, NULL);

  gchar* sane_path = path_sanitize_slashes(path); /* always succeeds */
  gchar** pathv = g_strsplit(sane_path, "/", 0);
  g_free(sane_path);

  return pathv;
}

static gchar* path_simplify(const gchar* path)
{
  gchar **pathv, **sane_pathv;
  guint i, j = 0, pathv_len, subroot = 0;
  gboolean absolute;

  g_return_val_if_fail(path != NULL, NULL);
  
  pathv = path_get_elements(path); /* should free */
  pathv_len = g_strv_length(pathv);
  
  sane_pathv = (gchar**)g_malloc0((pathv_len + 1) * sizeof(gchar*));
  absolute = (pathv_len > 1 && **pathv == '\0');
  
  for (i = 0; i < pathv_len; i++)
  {
    if (!strcmp(pathv[i], "."))
      continue; /* ignore curdirs in path */
    else if (!strcmp(pathv[i], ".."))
    {
      if (absolute)
      {
        if (j > 1)
        {
          j--;
        }
      }
      else
      {
        if (subroot && !strcmp(sane_pathv[j - 1], "..")) /* if we are off base and last item is .. */
        {
          sane_pathv[j++] = pathv[i];
        }
        else
        {
          if (j > subroot)
          {
            j--;
          }
          else
          {
            subroot++;
            sane_pathv[j++] = pathv[i];
          }
        }
      }
    }
    else
    {
      sane_pathv[j++] = pathv[i];
    }
  }

  sane_pathv[j] = 0;
  gchar* simple_path = g_strjoinv("/", sane_pathv);

  g_strfreev(pathv);
  g_free(sane_pathv);

  return simple_path;
}

// }}}

// Public API helpers

// {{{ send_status

static void init_status(mega_session* s, gint type)
{
  memset(&s->status_data, 0, sizeof(s->status_data));
  s->status_data.type = type;
}

// true to interrupt
static gboolean send_status(mega_session* s)
{
  if (s->status_callback) 
    return s->status_callback(&s->status_data, s->status_userdata);

  return FALSE;
}

// }}}
// {{{ add_share_key

void add_share_key(mega_session* s, const gchar* handle, const guchar* key)
{
  g_return_if_fail(s != NULL);
  g_return_if_fail(handle != NULL);
  g_return_if_fail(key != NULL);

  g_hash_table_insert(s->share_keys, g_strdup(handle), g_memdup(key, 16));
}

// }}}
// {{{ mega_node_parse

static mega_node* mega_node_parse(mega_session* s, const gchar* node)
{
  gchar* node_h = s_json_get_member_string(node, "h");
  gchar* node_p = s_json_get_member_string(node, "p");
  gchar* node_u = s_json_get_member_string(node, "u");
  gchar* node_k = s_json_get_member_string(node, "k");
  gchar* node_a = s_json_get_member_string(node, "a");
  gchar* node_sk = s_json_get_member_string(node, "sk");
  gchar* node_su = s_json_get_member_string(node, "su");
  gint node_t = s_json_get_member_int(node, "t", -1);
  gint64 node_ts = s_json_get_member_int(node, "ts", 0);
  gint64 node_s = s_json_get_member_int(node, "s", 0);

  // sanity check parsed values
  if (!node_h || strlen(node_h) == 0)
  {
    g_printerr("WARNING: Skipping FS node without handle\n");
    goto err0;
  }

  // return special nodes
  if (node_t == MEGA_NODE_ROOT)
  {
    mega_node* n = g_new0(mega_node, 1);
    n->name = g_strdup("Root");
    n->handle = g_strdup(node_h);
    n->timestamp = node_ts;
    n->type = node_t;
    return n;
  }
  else if (node_t == MEGA_NODE_INBOX)
  {
    mega_node* n = g_new0(mega_node, 1);
    n->name = g_strdup("Inbox");
    n->handle = g_strdup(node_h);
    n->timestamp = node_ts;
    n->type = node_t;
    return n;
  }
  else if (node_t == MEGA_NODE_TRASH)
  {
    mega_node* n = g_new0(mega_node, 1);
    n->name = g_strdup("Trash");
    n->handle = g_strdup(node_h);
    n->timestamp = node_ts;
    n->type = node_t;
    return n;
  }

  // allow only file and dir nodes
  if (node_t != MEGA_NODE_FOLDER && node_t != MEGA_NODE_FILE)
  {
    g_printerr("WARNING: Skipping FS node %s with unknown type %d\n", node_h, node_t);
    goto err0;
  }

  // node has to have attributes
  if (!node_a || strlen(node_a) == 0)
  {
    g_printerr("WARNING: Skipping FS node %s without attributes\n", node_h);
    goto err0;
  }

  // node has to have a key
  if (!node_k || strlen(node_k) == 0)
  {
    g_printerr("WARNING: Skipping FS node %s because of missing node key\n", node_h);
    goto err0;
  }

  // process sk if available
  if (node_sk && strlen(node_sk) > 0)
  {
    gsize share_key_len;
    guchar* share_key;

    if (strlen(node_sk) > 22)
    {
      share_key = b64_rsa_decrypt(node_sk, &s->rsa_key, &share_key_len);
      if (share_key && share_key_len >= 16)
        add_share_key(s, node_h, share_key);
    }
    else
    {
      share_key = b64_aes128_decrypt(node_sk, s->master_key, &share_key_len);
      if (share_key && share_key_len == 16)
        add_share_key(s, node_h, share_key);
    }

    g_free(share_key);
  }

  gchar* node_share_key = NULL;
  gchar* encrypted_node_key = NULL;
  gchar** parts = g_strsplit(node_k, "/", 0);
  gint i;

  for (i = 0; parts[i]; i++)
  {
    // split node keys
    gchar* key_value = strchr(parts[i], ':');
    if (key_value)
    {
      gchar* key_handle = parts[i];
      *key_value = '\0'; key_value++;

      if (s->user_handle && !strcmp(s->user_handle, key_handle))
      {
        // we found a key encrypted by me
        encrypted_node_key = g_strdup(key_value);
        node_share_key = s->master_key;
        break;
      }

      node_share_key = g_hash_table_lookup(s->share_keys, key_handle);
      if (node_share_key)
      {
        encrypted_node_key = g_strdup(key_value);
      }
    }
  }

  g_strfreev(parts);

  if (!encrypted_node_key)
  {
    g_printerr("WARNING: Skipping FS node %s because node key wasn't found\n", node_h);
    goto err1;
  }

  // keys longer than 45 chars are RSA keys
  if (strlen(encrypted_node_key) >= 46)
  {
    g_printerr("WARNING: Skipping FS node %s because it has RSA key\n", node_h);
    goto err1;
  }

  // decrypt node key
  gsize node_key_len = 0;
  guchar* node_key = b64_aes128_decrypt(encrypted_node_key, node_share_key, &node_key_len);
  if (!node_key)
  {
    g_printerr("WARNING: Skipping FS node %s because key can't be decrypted %s\n", node_h, encrypted_node_key);
    goto err1;
  }

  if (node_t == MEGA_NODE_FILE && node_key_len != 32)
  {
    g_printerr("WARNING: Skipping FS node %s because file key doesn't have 32 bytes\n", node_h);
    goto err2;
  }

  if (node_t == MEGA_NODE_FOLDER && node_key_len != 16)
  {
    g_printerr("WARNING: Skipping FS node %s because folder key doesn't have 16 bytes\n", node_h);
    goto err2;
  }

  // decrypt attributes with node key
  guchar aes_key[16];
  if (node_t == MEGA_NODE_FILE)
    unpack_node_key(node_key, aes_key, NULL, NULL);
  else
    memcpy(aes_key, node_key, 16);

  gchar* node_name = NULL;
  if (!decrypt_node_attrs(node_a, aes_key, &node_name))
  {
    g_printerr("WARNING: Skipping FS node %s because it has malformed attributes\n", node_h);
    goto err2;
  }

  if (!node_name)
  {
    g_printerr("WARNING: Skipping FS node %s because it is missing name\n", node_h);
    goto err2;
  }

  // check for invalid characters in the name
#ifdef G_OS_WIN32
  if (strpbrk(node_name, "/\\<>:\"|?*") || !strcmp(node_name, ".") || !strcmp(node_name, ".."))
#else
  if (strpbrk(node_name, "/") || !strcmp(node_name, ".") || !strcmp(node_name, "..")) 
#endif
  {
    g_printerr("WARNING: Skipping FS node %s because it's name is invalid '%s'\n", node_h, node_name);
    goto err3;
  }

  mega_node* n = g_new0(mega_node, 1);
  n->s = s;
  n->name = node_name;
  n->handle = node_h;
  n->parent_handle = node_p;
  n->user_handle = node_u;
  n->su_handle = node_su;
  n->key_len = node_key_len;
  n->key = node_key;
  n->size = node_s;
  n->timestamp = node_ts;
  n->type = node_t;

  g_free(encrypted_node_key);

  g_free(node_k);
  g_free(node_a);
  g_free(node_sk);

  return n;

err3:
  g_free(node_name);
err2:
  g_free(node_key);
err1:
  g_free(encrypted_node_key);
err0:
  g_free(node_h);
  g_free(node_p);
  g_free(node_u);
  g_free(node_k);
  g_free(node_a);
  g_free(node_sk);
  g_free(node_su);
  //print_node(node, "IGNORED_NODE = ");
  return NULL;
}

// }}}
// {{{ mega_node_parse_user

static mega_node* mega_node_parse_user(mega_session* s, const gchar* node)
{
  gchar* node_u = s_json_get_member_string(node, "u");
  gchar* node_m = s_json_get_member_string(node, "m");
  gint64 node_ts = s_json_get_member_int(node, "ts", 0);

  // sanity check parsed values
  if (!node_u || strlen(node_u) == 0)
    goto err;

  if (!node_m || strlen(node_m) == 0)
    goto err;

  mega_node* n = g_new0(mega_node, 1);
  n->s = s;
  n->name = node_m;
  n->handle = node_u;
  n->parent_handle = g_strdup("NETWORK");
  n->user_handle = g_strdup(node_u);
  n->timestamp = node_ts;
  n->type = MEGA_NODE_CONTACT;

  return n;

err:
  g_free(node_u);
  g_free(node_m);
  return NULL;
}

// }}}
// {{{ mega_node_is_writable

gboolean mega_node_is_writable(mega_session* s, mega_node* n)
{
  g_return_val_if_fail(n != NULL, FALSE);

  return n->type == MEGA_NODE_CONTACT 
    || ((n->type == MEGA_NODE_FILE || n->type == MEGA_NODE_FOLDER) && !strcmp(s->user_handle, n->user_handle))
    || n->type == MEGA_NODE_ROOT
    || n->type == MEGA_NODE_NETWORK
    || n->type == MEGA_NODE_TRASH;
}

// }}}
// {{{ mega_node_free

static void mega_node_free(mega_node* n)
{
  if (n)
  {
    g_free(n->name);
    g_free(n->handle);
    g_free(n->parent_handle);
    g_free(n->user_handle);
    g_free(n->su_handle);
    g_free(n->key);
    g_free(n->link);
    g_free(n->path);
    memset(n, 0, sizeof(mega_node));
    g_free(n);
  }
}

// }}}

// Public API

// {{{ mega_error_quark

GQuark mega_error_quark(void)
{
  return g_quark_from_static_string("mega-error-quark");
}

// }}}

// {{{ mega_session_new

mega_session* mega_session_new(void)
{
  mega_session* s = g_new0(mega_session, 1);

  s->http = mega_http_client_new();
  mega_http_client_set_content_type(s->http, "application/json");

  s->id = time(NULL);
  s->rid = make_request_id();

  s->share_keys = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

  return s;
}

// }}}
// {{{ mega_session_free

void mega_session_free(mega_session* s)
{
  if (s)
  {
    g_object_unref(s->http);
    g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
    if (s->fs_pathmap)
      g_hash_table_destroy(s->fs_pathmap);
    g_hash_table_destroy(s->share_keys);
    g_free(s->sid);
    g_free(s->rid);
    g_free(s->password_key);
    g_free(s->master_key);
    rsa_key_free(&s->rsa_key);
    g_free(s->user_handle);
    g_free(s->user_name);
    g_free(s->user_email);
    memset(s, 0, sizeof(mega_session));
    g_free(s);
  }
}

// }}}
// {{{ mega_session_watch_status

void mega_session_watch_status(mega_session* s, mega_status_callback cb, gpointer userdata)
{
  g_return_if_fail(s != NULL);

  s->status_callback = cb;
  s->status_userdata = userdata;
}

// }}}

// {{{ mega_session_open_exp_folder

gboolean mega_session_open_exp_folder(mega_session* s, const gchar* n, const gchar* key, GError** err)
{
  GError* local_err = NULL;
  gsize len, i, l;
  GSList* list = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(n != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_session_close(s);

  s->sid_param_name = "n";
  s->sid = g_strdup(n);

  s->master_key = base64urldecode(key, &len);
  if (len != 16)
    return FALSE;

  // login user
  gchar* f_node = api_call(s, 'o', NULL, &local_err, "[{a:f, c:1, r:1}]");
  if (!f_node)
  {
    g_propagate_error(err, local_err);
    return FALSE;
  }

  const gchar* ff_node = s_json_get_member(f_node, "f");
  if (ff_node && s_json_get_type(ff_node) == S_JSON_TYPE_ARRAY)
  {
    const gchar* node;
    gint i = 0;

    while ((node = s_json_get_element(ff_node, i++)))
    {
      if (s_json_get_type(node) == S_JSON_TYPE_OBJECT)
      {
        // first node is the root folder
        if (i == 1)
        {
          gchar* node_h = s_json_get_member_string(node, "h");
          add_share_key(s, node_h, s->master_key);
          g_free(node_h);
        }

        // import nodes into the fs
        mega_node* n = mega_node_parse(s, node);
        if (n)
        {
          if (i == 1)
          {
            g_free(n->parent_handle);
            n->parent_handle = NULL;
          }

          list = g_slist_prepend(list, n);
        }
      }
    }
  }

  s->fs_nodes = g_slist_reverse(list);
  update_pathmap(s);

  g_free(f_node);
  return TRUE;
}

// }}}
// {{{ mega_session_open

gboolean mega_session_open(mega_session* s, const gchar* un, const gchar* pw, const gchar* sid, GError** err)
{
  GError* local_err = NULL;
  gboolean is_loggedin = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(un != NULL, FALSE);
  g_return_val_if_fail(pw != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_session_close(s);

  //g_print("%s %s %s\n", un, pw, sid);

  // make password key
  g_free(s->password_key);
  s->password_key = make_password_key(pw);

  // if we have existing session id, just check with the server if session is
  // active, and download keys and user info
  if (sid)
  {
    g_free(s->sid);
    s->sid = g_strdup(sid);

    is_loggedin = mega_session_get_user(s, NULL);
  }

  if (!is_loggedin)
  {
    gchar* un_lower = g_ascii_strdown(un, -1);
    gchar* uh = make_username_hash(un_lower, s->password_key);

    // login user
    gchar* login_node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%S, uh:%S}]", un_lower, uh);
    if (!login_node)
    {
      g_propagate_error(err, local_err);
      goto err;
    }

    gchar* login_k = s_json_get_member_string(login_node, "k");
    gchar* login_privk = s_json_get_member_string(login_node, "privk");
    gchar* login_csid = s_json_get_member_string(login_node, "csid");

    // decrypt master key
    guchar* master_key = b64_aes128_decrypt(login_k, s->password_key, NULL);
    if (!master_key)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read master key during login");
      goto err1;
    }

    // decrypt private key with master key
    rsa_key privk;
    memset(&privk, 0, sizeof(privk));
    if (!b64_aes128_decrypt_privk(login_privk, master_key, &privk))
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read private key during login");
      rsa_key_free(&privk);
      g_free(master_key);
      goto err1;
    }

    g_free(master_key);

    // decrypt session id
    gsize sid_len = 0;
    guchar* sid = b64_rsa_decrypt(login_csid, &privk, &sid_len);
    if (!sid || sid_len < 43) 
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read session id during login");
      rsa_key_free(&privk);
      goto err1;
    }

    // save session id
    g_free(s->sid);
    s->sid = base64urlencode(sid, 43);

    // cleanup
    g_free(sid);
    rsa_key_free(&privk);
    g_free(login_node);

    g_free(login_k);
    g_free(login_privk);
    g_free(login_csid);

    return mega_session_get_user(s, err);

  err1:
    g_free(login_k);
    g_free(login_privk);
    g_free(login_csid);
  err:
    g_free(login_node);
    return FALSE;
  }

  return TRUE;
}

// }}}
// {{{ mega_session_close

void mega_session_close(mega_session* s)
{
  g_return_if_fail(s != NULL);

  g_free(s->password_key);
  g_free(s->master_key);
  g_free(s->sid);
  rsa_key_free(&s->rsa_key);
  g_free(s->user_handle);
  g_free(s->user_name);
  g_free(s->user_email);

  g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
  if (s->fs_pathmap)
    g_hash_table_destroy(s->fs_pathmap);

  g_hash_table_remove_all(s->share_keys);

  s->password_key = NULL;
  s->master_key = NULL;
  s->sid = NULL;
  s->user_handle = NULL;
  s->user_email = NULL;
  s->user_name = NULL;
  s->fs_pathmap = NULL;
  s->fs_nodes = NULL;
  s->last_refresh = 0;

  s->status_callback = NULL;
}

// }}}
// {{{ mega_session_get_sid

const gchar* mega_session_get_sid(mega_session* s)
{
  g_return_val_if_fail(s != NULL, NULL);

  return s->sid;
}

// }}}
// {{{ mega_session_get_user

gboolean mega_session_get_user(mega_session* s, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->sid != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  // prepare request
  gchar* user_node = api_call(s, 'o', NULL, &local_err, "[{a:ug}]");
  if (!user_node)
  {
    g_propagate_error(err, local_err);
    goto err;
  }

  // store information about the user
  g_free(s->user_handle);
  s->user_handle = s_json_get_member_string(user_node, "u");
  if (!s->user_handle)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read user's handle");
    goto err;
  }

  g_free(s->user_email);
  s->user_email = s_json_get_member_string(user_node, "email");

  g_free(s->user_name);
  s->user_name = s_json_get_member_string(user_node, "name");

  gchar* user_privk = s_json_get_member_string(user_node, "privk");
  gchar* user_pubk = s_json_get_member_string(user_node, "pubk");
  gchar* user_k = s_json_get_member_string(user_node, "k");

  // load master key
  g_free(s->master_key);
  s->master_key = b64_aes128_decrypt(user_k, s->password_key, NULL);
  if (!s->master_key)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read master key");
    goto err1;
  }

  rsa_key_free(&s->rsa_key);

  // decrypt private key with master key
  if (!b64_aes128_decrypt_privk(user_privk, s->master_key, &s->rsa_key))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read private key");
    goto err1;
  }

  // load public key
  if (!b64_decode_pubk(user_pubk, &s->rsa_key))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't read public key");
    goto err1;
  }

  s->last_refresh = time(NULL);

  g_free(user_privk);
  g_free(user_pubk);
  g_free(user_k);
  g_free(user_node);
  return TRUE;

err1:
  g_free(user_privk);
  g_free(user_pubk);
  g_free(user_k);
err:
  g_free(user_node);
  return FALSE;
}

// }}}
// {{{ mega_session_refresh

gboolean mega_session_refresh(mega_session* s, GError** err)
{
  GError* local_err = NULL;
  GSList* list = NULL;
  gint i, l;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  // prepare request
  gchar* f_node = api_call(s, 'o', NULL, &local_err, "[{a:f, c:1}]");
  if (!f_node)
  {
    g_propagate_error(err, local_err);
    goto err;
  }

  if (mega_debug & MEGA_DEBUG_FS)
    print_node(f_node, "FS: ");

  // process 'ok' array
  const gchar* ok_node = s_json_get_member(f_node, "ok");
  if (ok_node && s_json_get_type(ok_node) == S_JSON_TYPE_ARRAY)
  {
    gchar** oks = s_json_get_elements(ok_node);

    for (i = 0, l = g_strv_length(oks); i < l; i++)
    {
      const gchar* ok = oks[i];
      if (s_json_get_type(ok) != S_JSON_TYPE_OBJECT)
        continue;

      gchar* ok_h = s_json_get_member_string(ok, "h");    // h.8 
      gchar* ok_ha = s_json_get_member_string(ok, "ha");  // b64(aes(h.8 h.8, master_key))
      gchar* ok_k = s_json_get_member_string(ok, "k");    // b64(aes(share_key_for_h, master_key))

      if (!ok_h || !ok_ha ||!ok_k)
      {
        g_printerr("WARNING: Skipping import of a key %s because it's missing required attributes\n", ok_h);
        goto skip;
      }

      if (!handle_auth(ok_h, ok_ha, s->master_key))
      {
        g_printerr("WARNING: Skipping import of a key %s because it's authentication failed\n", ok_h);
        goto skip;
      }

      //g_print("Importing key %s:%s\n", ok_h, ok_k);

      guchar* key = b64_aes128_decrypt(ok_k, s->master_key, NULL);
      add_share_key(s, ok_h, key);
      g_free(key);

    skip:
      g_free(ok_h);
      g_free(ok_ha);
      g_free(ok_k);
    }

    g_free(oks);
  }

  // process 'f' array
  const gchar* ff_node = s_json_get_member(f_node, "f");
  if (!ff_node || s_json_get_type(ff_node) != S_JSON_TYPE_ARRAY)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote filesystem 'f' node is invalid");
    goto err;
  }

  gchar** ff_arr = s_json_get_elements(ff_node);
  for (i = 0, l = g_strv_length(ff_arr); i < l; i++)
  {
    const gchar* f = ff_arr[i];
    if (s_json_get_type(f) != S_JSON_TYPE_OBJECT)
      continue;

    mega_node* n = mega_node_parse(s, f);
    if (n)
      list = g_slist_prepend(list, n);
  }

  g_free(ff_arr);

  // import special root node for contacts
  mega_node* n = g_new0(mega_node, 1);
  n->s = s;
  n->name = g_strdup("Contacts");
  n->handle = g_strdup("NETWORK");
  n->type = MEGA_NODE_NETWORK;
  list = g_slist_prepend(list, n);

  // process 'u' array
  const gchar* u_node = s_json_get_member(f_node, "u");
  if (u_node && s_json_get_type(u_node) == S_JSON_TYPE_ARRAY)
  {
    gchar** u_arr = s_json_get_elements(u_node);
    for (i = 0, l = g_strv_length(u_arr); i < l; i++)
    {
      const gchar* u = u_arr[i];
      if (s_json_get_type(u) != S_JSON_TYPE_OBJECT)
        continue;

      gint64 u_c = s_json_get_member_int(u, "c", 0);

      // skip self and removed
      if (u_c != 1)
        continue;

      mega_node* n = mega_node_parse_user(s, u);
      if (n) 
        list = g_slist_prepend(list, n);
    }
    g_free(u_arr);
  }

  g_free(f_node);

  // replace existing nodes
  g_slist_free_full(s->fs_nodes, (GDestroyNotify)mega_node_free);
  s->fs_nodes = g_slist_reverse(list);

  update_pathmap(s);

  s->last_refresh = time(NULL);

  return TRUE;

err:
  g_free(f_node);
  return FALSE;
}

// }}}
// {{{ mega_session_addlinks

gboolean mega_session_addlinks(mega_session* s, GSList* nodes, GError** err)
{
  GError* local_err = NULL;
  GSList* i;
  GPtrArray* rnodes;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  if (g_slist_length(nodes) == 0)
    return TRUE;

  rnodes = g_ptr_array_sized_new(g_slist_length(nodes));

  // prepare request
  SJsonGen *gen = s_json_gen_new();
  s_json_gen_start_array(gen);
  for (i = nodes; i; i = i->next)
  {
    mega_node* n = i->data;

    if (n->type == MEGA_NODE_FILE)
    {
      s_json_gen_start_object(gen);
      s_json_gen_member_string(gen, "a", "l");
      s_json_gen_member_string(gen, "n", n->handle);
      s_json_gen_end_object(gen);

      g_ptr_array_add(rnodes, n);
    }
  }
  s_json_gen_end_array(gen);
  gchar *request = s_json_gen_done(gen);

  // perform request
  gchar* response = api_request(s, request, &local_err);
  g_free(request);

  // process response
  if (!response)
  {
    g_propagate_prefixed_error(err, local_err, "API call 'l' failed: ");
    g_ptr_array_free(rnodes, TRUE);
    return FALSE;
  }
  
  if (s_json_get_type(response) == S_JSON_TYPE_ARRAY)
  {
    gchar** nodes_arr = s_json_get_elements(response);
    gint i, l = g_strv_length(nodes_arr);

    if (l != rnodes->len)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "API call 'l' results mismatch");
      g_ptr_array_free(rnodes, TRUE);
      g_free(nodes_arr);
      g_free(response);
      return FALSE;
    }

    for (i = 0; i < l; i++)
    {
      gchar* link = s_json_get_string(nodes_arr[i]);

      mega_node* n = g_ptr_array_index(rnodes, i);

      g_free(n->link);
      n->link = link;
    }

    g_free(nodes_arr);
  }

  g_free(response);
  g_ptr_array_free(rnodes, TRUE);

  return TRUE;
}

// }}}
// {{{ mega_session_user_quota

mega_user_quota* mega_session_user_quota(mega_session* s, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  // prepare request
  gchar* quota_node = api_call(s, 'o', NULL, &local_err, "[{a:ug, strg:1, xfer:1, pro:1}]");
  if (!quota_node)
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  mega_user_quota* q = g_new0(mega_user_quota, 1);

  q->total = s_json_get_member_int(quota_node, "mstrg", 0);
  q->used = s_json_get_member_int(quota_node, "cstrg", 0);

  g_free(quota_node);

  return q;
}

// }}}

// {{{ mega_session_ls_all

static void _ls_all(gchar* path, mega_node* n, GSList** l)
{
  *l = g_slist_prepend(*l, n);
}

// free gslist, not the data
GSList* mega_session_ls_all(mega_session* s)
{
  GSList* list = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);

  g_hash_table_foreach(s->fs_pathmap, (GHFunc)_ls_all, &list);

  return g_slist_sort(list, (GCompareFunc)strcmp);
}

// }}}
// {{{ mega_session_ls

struct _ls_data
{
  GSList* list;
  gchar* path;
  gboolean recursive;
};

static void _ls(gchar* path, mega_node* n, struct _ls_data* data)
{
  if (g_str_has_prefix(path, data->path) && (data->recursive || !strchr(path + strlen(data->path), '/')))
    data->list = g_slist_prepend(data->list, n);
}

// free gslist, not the data
GSList* mega_session_ls(mega_session* s, const gchar* path, gboolean recursive)
{
  struct _ls_data data;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);

  gchar* tmp = path_simplify(path);

  if (!strcmp(tmp, "/"))
    data.path = g_strdup("/");
  else
    data.path = g_strdup_printf("%s/", tmp);
  data.recursive = recursive;
  data.list = NULL;
  g_free(tmp);

  g_hash_table_foreach(s->fs_pathmap, (GHFunc)_ls, &data);

  g_free(data.path);
  return data.list;
}

// }}}
// {{{ mega_session_stat

mega_node* mega_session_stat(mega_session* s, const gchar* path)
{
  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);

  gchar* tmp = path_simplify(path);
  mega_node* n = g_hash_table_lookup(s->fs_pathmap, path);
  g_free(tmp);

  return n;
}

// }}}
// {{{ mega_session_get_node_chilren

GSList* mega_session_get_node_chilren(mega_session* s, mega_node* node)
{
  GSList *list = NULL, *i;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(node != NULL, NULL);
  g_return_val_if_fail(node->handle != NULL, NULL);

  for (i = s->fs_nodes; i; i = i->next)
  {
    mega_node* child = i->data;

    if (child->parent_handle && !strcmp(child->parent_handle, node->handle))
      list = g_slist_prepend(list, child);
  }

  return g_slist_reverse(list);
}

// }}}
// {{{ mega_session_mkdir

mega_node* mega_session_mkdir(mega_session* s, const gchar* path, GError** err)
{
  GError* local_err = NULL;
  mega_node* n = NULL;
  gchar* mkdir_node = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  mega_node* d = mega_session_stat(s, path);
  if (d)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory already exists: %s", path);
    return NULL;
  }

  gchar* tmp = path_simplify(path);
  gchar* parent_path = g_path_get_dirname(tmp);
  g_free(tmp);

  if (!strcmp(parent_path, "/"))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create toplevel dir: %s", path);
    g_free(parent_path);
    return NULL;
  }

  mega_node* p = mega_session_stat(s, parent_path);
  if (!p || p->type == MEGA_NODE_FILE || p->type == MEGA_NODE_INBOX)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s", parent_path);
    g_free(parent_path);
    return NULL;
  }

  if (!mega_node_is_writable(s, p))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory is not writable: %s", parent_path);
    g_free(parent_path);
    return NULL;
  }

  g_free(parent_path);

  if (p->type == MEGA_NODE_NETWORK)
  {
    // prepare contact add request
    gchar* ur_node = api_call(s, 'o', NULL, &local_err, "[{a:ur, u:%S, l:1, i:%s}]", g_path_get_basename(path), s->rid);
    if (!ur_node)
    {
      g_propagate_error(err, local_err);
      return NULL;
    }

    // parse response
    n = mega_node_parse_user(s, ur_node);
    if (!n)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      g_free(ur_node);
      return NULL;
    }

    g_free(ur_node);
  }
  else
  {
    guchar* node_key = make_random_key();
    gchar* basename = g_path_get_basename(path);
    gchar* attrs = encode_node_attrs(basename);
    gchar* dir_attrs = b64_aes128_cbc_encrypt_str(attrs, node_key);
    gchar* dir_key = b64_aes128_encrypt(node_key, 16, s->master_key);
    g_free(basename);
    g_free(attrs);
    g_free(node_key);

    // prepare request
    mkdir_node = api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, i:%s, n: [{h:xxxxxxxx, t:1, k:%S, a:%S}]}]", p->handle, s->rid, dir_key, dir_attrs);
    if (!mkdir_node)
    {
      g_propagate_error(err, local_err);
      goto err;
    }

    const gchar* f_arr = s_json_get_member(mkdir_node, "f");
    if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    const gchar* f_el = s_json_get_element(f_arr, 0);
    if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    n = mega_node_parse(s, f_el);
    if (!n)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
      goto err;
    }

    g_free(mkdir_node);
  }

  // add mkdired node to the filesystem
  s->fs_nodes = g_slist_append(s->fs_nodes, n);
  update_pathmap(s);

  return n;

err:
  g_free(mkdir_node);
  return NULL;
}

// }}}
// {{{ mega_session_rm

gboolean mega_session_rm(mega_session* s, const gchar* path, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->fs_pathmap != NULL, FALSE);
  g_return_val_if_fail(path != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_node* mn = mega_session_stat(s, path);
  if (!mn)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File not found: %s", path);
    return FALSE;
  }

  if (!mega_node_is_writable(s, mn))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File is not removable: %s", path);
    return FALSE;
  }

  if (mn->type == MEGA_NODE_FILE || mn->type == MEGA_NODE_FOLDER)
  {
    // prepare request
    gchar* rm_node = api_call(s, 'i', NULL, &local_err, "[{a:d, i:%s, n:%s}]", s->rid, mn->handle);
    if (!rm_node)
    {
      g_propagate_error(err, local_err);
      return FALSE;
    }

    g_free(rm_node);
  }
  else if (mn->type == MEGA_NODE_CONTACT)
  {
    gchar* ur_node = api_call(s, 'i', NULL, &local_err, "[{a:ur, u:%s, l:0, i:%s}]", mn->handle, s->rid);
    if (!ur_node)
    {
      g_propagate_error(err, local_err);
      return FALSE;
    }

    g_free(ur_node);
  }
  else
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't remove system dir %s", path);
    return FALSE;
  }

  // remove node from the filesystem
  s->fs_nodes = g_slist_remove(s->fs_nodes, mn);
  mega_node_free(mn);
  update_pathmap(s);

  return TRUE;
}

// }}}
// {{{ mega_session_new_node_attribute

gchar* mega_session_new_node_attribute(mega_session* s, const guchar* data, gsize len, const gchar* type, const guchar* key, GError** err)
{
  GError* local_err = NULL;
  guchar* plain;
  AES_KEY k;
  guchar* cipher;
  guchar iv[AES_BLOCK_SIZE] = {0};
  gsize pad = len % 16 ? 16 - (len % 16) : 0;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);
  g_return_val_if_fail(type != NULL, NULL);
  g_return_val_if_fail(key != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  gchar* ufa_node = api_call(s, 'o', NULL, &local_err, "[{a:ufa, s:%i, ssl:0}]", (gint64)len + pad);
  if (!ufa_node)
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  gchar* p_url = s_json_get_member_string(ufa_node, "p");
  g_free(ufa_node);

  // encrypt
  AES_set_encrypt_key(key, 128, &k);
  plain = g_memdup(data, len);
  plain = g_realloc(plain, len + pad);
  memset(plain + len, 0, pad);
  cipher = g_malloc0(len + pad);
  AES_cbc_encrypt(plain, cipher, len + pad, &k, iv, 1);
  g_free(plain);

  // upload
  http* h = http_new();
  http_set_content_type(h, "application/octet-stream");
  GString* handle = http_post(h, p_url, cipher, len + pad, &local_err);
  http_free(h);
  g_free(cipher);
  g_free(p_url);

  if (!handle)
  {
    g_propagate_prefixed_error(err, local_err, "Node attribute data upload failed: ");
    g_string_free(handle, TRUE);
    return NULL;
  }

  if (handle->len != 8)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Node attribute handle is invalid");
    g_string_free(handle, TRUE);
    return NULL;
  }

  gchar* b64_handle = base64urlencode(handle->str, handle->len);
  g_string_free(handle, TRUE);
  gchar* tmp = g_strdup_printf("%s*%s", type, b64_handle);
  g_free(b64_handle);

  return tmp;
}

// }}}
// {{{ create_preview

static gint has_convert = -1;
static gint has_ffmpegthumbnailer = -1;

static gchar* create_preview(mega_session* s, const gchar* local_path, const guchar* key, GError** err)
{
  gchar* handle = NULL;
#ifndef G_OS_WIN32
  GError* local_err = NULL;
  gchar *tmp1 = NULL, *tmp2 = NULL, *prg;

  if (has_ffmpegthumbnailer < 0)
  {
    prg = g_find_program_in_path("ffmpegthumbnailer");
    has_ffmpegthumbnailer = !!prg;
    g_free(prg);
  }

  if (has_convert < 0)
  {
    prg = g_find_program_in_path("convert");
    has_ffmpegthumbnailer = !!prg;
    g_free(prg);
  }

  if (has_ffmpegthumbnailer && g_regex_match_simple("\\.(mpg|mpeg|avi|mkv|flv|rm|mp4|wmv|asf|ram|mov)$", local_path, G_REGEX_CASELESS, 0))
  {
    gchar buf[50] = "/tmp/megatools.XXXXXX";
    gchar* dir = g_mkdtemp(buf);
    if (dir)
    {
      gint status = 1;
      gchar* thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
      gchar* qpath = g_shell_quote(local_path);
      gchar* tmp = g_strdup_printf("ffmpegthumbnailer -t 5 -i %s -o %s/thumb.jpg -s 128 -f -a", qpath, dir);

      if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, &local_err))
      {
        if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR))
        {
          gchar* thumb_data;
          gsize thumb_len;

          if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL))
          {
            handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0", key, &local_err);
            if (!handle)
              g_propagate_error(err, local_err);

            g_free(thumb_data);
          }

          g_unlink(thumb_path);
        }
      }
      else
      {
        g_propagate_error(err, local_err);
      }

      g_rmdir(dir);
      g_free(tmp);
      g_free(qpath);
      g_free(thumb_path);
    }
  }
  else if (has_convert && g_regex_match_simple("\\.(jpe?g|png|gif|bmp|tiff|svg|pnm|eps|ico|pdf)$", local_path, G_REGEX_CASELESS, 0))
  {
    gchar buf[50] = "/tmp/megatools.XXXXXX";
    gchar* dir = g_mkdtemp(buf);
    if (dir)
    {
      gint status = 1;
      gchar* thumb_path = g_strdup_printf("%s/thumb.jpg", dir);
      gchar* qpath = g_shell_quote(local_path);
      gchar* tmp = g_strdup_printf("convert %s -strip -resize 128x128^ -gravity center -crop 128x128+0+0 +repage %s/thumb.jpg", qpath, dir);

      if (g_spawn_command_line_sync(tmp, &tmp1, &tmp2, &status, NULL))
      {
        if (g_file_test(thumb_path, G_FILE_TEST_IS_REGULAR))
        {
          gchar* thumb_data;
          gsize thumb_len;

          if (g_file_get_contents(thumb_path, &thumb_data, &thumb_len, NULL))
          {
            handle = mega_session_new_node_attribute(s, thumb_data, thumb_len, "0", key, &local_err);
            if (!handle)
              g_propagate_error(err, local_err);

            g_free(thumb_data);
          }

          g_unlink(thumb_path);
        }
      }
      else
      {
        g_propagate_error(err, local_err);
      }

      g_rmdir(dir);
      g_free(tmp);
      g_free(qpath);
      g_free(thumb_path);
    }
  }
  else
  {
    return NULL;
  }

  g_free(tmp1);
  g_free(tmp2);

  if (!handle && err && !*err)
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't create preview");

#endif
  return handle;
}

// }}}
// {{{ mega_session_put

static gboolean progress_generic(goffset total, goffset now, mega_session* s)
{
  init_status(s, MEGA_STATUS_PROGRESS);
  s->status_data.progress.total = total;
  s->status_data.progress.done = now;
  if (send_status(s)) 
      return FALSE;

  return TRUE;
}

struct _put_data
{
  GFileInputStream* stream;
  AES_KEY k;
  guchar iv[AES_BLOCK_SIZE];
  gint num;
  guchar ecount[AES_BLOCK_SIZE];
  chunked_cbc_mac mac;
};

static gsize put_process_data(gpointer buffer, gsize size, struct _put_data* data)
{
  gsize bytes_read = 0;
  guchar* in_buffer = g_malloc(size);

  if (g_input_stream_read_all(G_INPUT_STREAM(data->stream), in_buffer, size, &bytes_read, NULL, NULL))
  {
    if (bytes_read > 0)
    {
      AES_ctr128_encrypt(in_buffer, buffer, bytes_read, &data->k, data->iv, data->ecount, &data->num);
      chunked_cbc_mac_update(&data->mac, in_buffer, bytes_read);
    }

    g_free(in_buffer);
    return bytes_read;
  }

  g_free(in_buffer);
  return 0;
}

mega_node* mega_session_put(mega_session* s, const gchar* remote_path, const gchar* local_path, GError** err)
{
  struct _put_data data;
  GError* local_err = NULL;
  mega_node *node, *parent_node;
  gchar* file_name = NULL;

  g_return_val_if_fail(s != NULL, NULL);
  g_return_val_if_fail(s->fs_pathmap != NULL, NULL);
  g_return_val_if_fail(remote_path != NULL, NULL);
  g_return_val_if_fail(local_path != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  memset(&data, 0, sizeof(data));

  // check remote filesystem, and get parent node

  node = mega_session_stat(s, remote_path);
  if (node)
  {
    if (node->type == MEGA_NODE_FILE)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", remote_path);
      return NULL;
    }
    else
    {
      // put into a dir
      parent_node = node;

      gchar* basename = g_path_get_basename(local_path);
      gchar* tmp = g_strconcat(remote_path, "/", basename, NULL);
      g_free(basename);
      node = mega_session_stat(s, tmp);
      if (node)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", tmp);
        g_free(tmp);
        return NULL;
      }
      g_free(tmp);

      if (!mega_node_is_writable(s, parent_node) || parent_node->type == MEGA_NODE_NETWORK || parent_node->type == MEGA_NODE_CONTACT)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory is not writable: %s", remote_path);
        return NULL;
      }

      file_name = g_path_get_basename(local_path);
    }
  }
  else
  {
    gchar* tmp = path_simplify(remote_path);
    gchar* parent_path = g_path_get_dirname(tmp);
    g_free(tmp);

    if (!strcmp(parent_path, "/"))
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't upload to toplevel dir: %s", remote_path);
      g_free(parent_path);
      return NULL;
    }

    parent_node = mega_session_stat(s, parent_path);
    if (!parent_node || parent_node->type == MEGA_NODE_FILE)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Parent directory doesn't exist: %s", parent_path);
      g_free(parent_path);
      return NULL;
    }

    if (!mega_node_is_writable(s, parent_node) || parent_node->type == MEGA_NODE_NETWORK || parent_node->type == MEGA_NODE_CONTACT)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Directory is not writable: %s", parent_path);
      g_free(parent_path);
      return NULL;
    }

    file_name = g_path_get_basename(remote_path);
    g_free(parent_path);
  }

  // open local file for reading, and get file size

  GFile* file = g_file_new_for_path(local_path);
  GFileInputStream* stream = g_file_read(file, NULL, &local_err);
  if (!stream)
  {
    g_propagate_prefixed_error(err, local_err, "Can't read local file %s: ", local_path);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }   

  GFileInfo* info = g_file_input_stream_query_info(stream, G_FILE_ATTRIBUTE_STANDARD_SIZE, NULL, &local_err);
  if (!info)
  {
    g_propagate_prefixed_error(err, local_err, "Can't read local file %s: ", local_path);
    g_object_unref(stream);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }

  goffset file_size = g_file_info_get_size(info);
  g_object_unref(info);

  // ask for upload url - [{"a":"u","ssl":0,"ms":0,"s":<SIZE>,"r":0,"e":0}]
  gchar* up_node = api_call(s, 'o', NULL, &local_err, "[{a:u, ssl:0, ms:0, s:%i, r:0, e:0}]", (gint64)file_size);
  if (!up_node)
  {
    g_propagate_error(err, local_err);
    g_object_unref(stream);
    g_object_unref(file);
    g_free(file_name);
    return NULL;
  }

  gchar* p_url = s_json_get_member_string(up_node, "p");
  g_free(up_node);

  // setup encryption
  guchar* aes_key = make_random_key();
  guchar* nonce = make_random_key();
  AES_set_encrypt_key(aes_key, 128, &data.k);
  memcpy(data.iv, nonce, 8);
  chunked_cbc_mac_init8(&data.mac, aes_key, nonce);

  data.stream = stream;

  // perform upload
  http* h = http_new();
  http_set_content_type(h, "application/octet-stream");
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  GString* up_handle = http_post_stream_upload(h, p_url, file_size, (http_data_fn)put_process_data, &data, &local_err);
  g_free(p_url);
  g_object_unref(stream);
  g_object_unref(file);

  if (!up_handle)
  {
    g_propagate_prefixed_error(err, local_err, "Data upload failed: ");
    goto err0;
  }

  // check for numeric error code
  if (up_handle->len < 10 && g_regex_match_simple("^-(\\d+)$", up_handle->str, 0, 0))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Server returned error code %s", srv_error_to_string(atoi(up_handle->str)));
    goto err0;
  }

  if (up_handle->len > 100 || !g_regex_match_simple("^[a-zA-Z0-9_+/-]{20,50}$", up_handle->str, 0, 0))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid upload handle");
    goto err0;
  }

  gchar* fa = create_preview(s, local_path, aes_key, NULL);

  gchar* attrs = encode_node_attrs(file_name);
  gchar* attrs_enc = b64_aes128_cbc_encrypt_str(attrs, aes_key);
  g_free(attrs);

  guchar meta_mac[16];
  guchar node_key[32];
  chunked_cbc_mac_finish(&data.mac, meta_mac);
  pack_node_key(node_key, aes_key, nonce, meta_mac);
  gchar* node_key_enc = b64_aes128_encrypt(node_key, 32, s->master_key);

  // prepare request
  gchar* put_node = api_call(s, 'o', NULL, &local_err, "[{a:p, t:%s, n:[{h:%s, t:0, k:%S, a:%S, fa:%s}]}]", parent_node->handle, up_handle->str, node_key_enc, attrs_enc, fa);
  if (!put_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  const gchar* f_arr = s_json_get_member(put_node, "f");
  if (s_json_get_type(f_arr) != S_JSON_TYPE_ARRAY)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  const gchar* f_el = s_json_get_element(f_arr, 0);
  if (!f_el || s_json_get_type(f_el) != S_JSON_TYPE_OBJECT)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  mega_node* nn = mega_node_parse(s, f_el);
  if (!nn)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid response");
    goto err1;
  }

  // add uploaded node to the filesystem
  s->fs_nodes = g_slist_append(s->fs_nodes, nn);
  update_pathmap(s);

  g_free(put_node);
  http_free(h);
  g_free(aes_key);
  g_free(nonce);
  g_string_free(up_handle, TRUE);
  return nn;

err1:
  g_free(put_node);
err0:
  http_free(h);
  g_free(aes_key);
  g_free(nonce);
  g_free(file_name);
  g_string_free(up_handle, TRUE);
  return NULL;
}

// }}}
// {{{ mega_session_get

struct _get_data
{
  mega_session* s;
  GOutputStream* stream;
  AES_KEY k;
  guchar iv[AES_BLOCK_SIZE];
  gint num;
  guchar ecount[AES_BLOCK_SIZE];
  chunked_cbc_mac mac;
};

static gsize get_process_data(gpointer buffer, gsize size, struct _get_data* data)
{
  gchar* out_buffer = g_malloc(size);

  AES_ctr128_encrypt(buffer, out_buffer, size, &data->k, data->iv, data->ecount, &data->num);

  chunked_cbc_mac_update(&data->mac, out_buffer, size);

  init_status(data->s, MEGA_STATUS_DATA);
  data->s->status_data.data.size = size;
  data->s->status_data.data.buf = out_buffer;
  if (send_status(data->s)) 
  {
    g_free(out_buffer);
    return 0;
  }

  if (!data->stream)
  {
    g_free(out_buffer);
    return size;
  }

  GError *local_err = NULL;
  gsize bytes_written = 0;
  if (g_output_stream_write_all(G_OUTPUT_STREAM(data->stream), out_buffer, size, &bytes_written, NULL, &local_err))
  {
    g_free(out_buffer);
    return size;
  }

  g_printerr("ERROR: get_process_data: write failed of size %u (bytes_written=%d): %s\n", (unsigned int)size, (int)bytes_written, local_err->message);
  g_free(out_buffer);
  return 0;
}

gboolean mega_session_get(mega_session* s, const gchar* local_path, const gchar* remote_path, GError** err)
{
  struct _get_data data;
  GError* local_err = NULL;
  GFile* file = NULL;
  gboolean remove_file = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->fs_pathmap != NULL, FALSE);
  g_return_val_if_fail(remote_path != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  memset(&data, 0, sizeof(data));
  data.s = s;

  mega_node* n = mega_session_stat(s, remote_path);
  if (!n)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file not found: %s", remote_path);
    return FALSE;
  }

  init_status(s, MEGA_STATUS_FILEINFO);
  s->status_data.fileinfo.name = n->name;
  s->status_data.fileinfo.size = n->size;
  if (send_status(s)) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Operation cancelled from status callback");
    return FALSE;
  }

  if (local_path)
  {
    file = g_file_new_for_path(local_path);
    if (g_file_query_exists(file, NULL))
    {
      if (g_file_query_file_type(file, 0, NULL) == G_FILE_TYPE_DIRECTORY)
      {
        GFile* child = g_file_get_child(file, n->name);
        if (g_file_query_exists(child, NULL))
        {
          g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Local file already exists: %s/%s", local_path, n->name);
          g_object_unref(file);
          g_object_unref(child);
          return FALSE;
        }
        else
        {
          g_object_unref(file);
          file = child;
        }
      }
      else
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Local file already exists: %s", local_path);
        g_object_unref(file);
        return FALSE;
      }
    }

    data.stream = G_OUTPUT_STREAM(g_file_create(file, 0, NULL, &local_err));
    if (!data.stream)
    {
      g_propagate_prefixed_error(err, local_err, "Can't open local file %s for writing: ", local_path);
      g_object_unref(file);
      return FALSE;
    }
  }

  remove_file = TRUE;

  // initialize decrytpion key/state
  guchar aes_key[16], meta_mac_xor[8];
  unpack_node_key(n->key, aes_key, data.iv, meta_mac_xor);
  AES_set_encrypt_key(aes_key, 128, &data.k);
  chunked_cbc_mac_init8(&data.mac, aes_key, data.iv);

  // prepare request
  gchar* get_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, n:%s}]", n->handle);

  if (!get_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  gint64 file_size = s_json_get_member_int(get_node, "s", -1);
  if (file_size < 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
    goto err0;
  }

  gchar* url = s_json_get_member_string(get_node, "g");
  if (!url)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
    goto err0;
  }

  // perform download
  http* h = http_new();
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  if (!http_post_stream_download(h, url, (http_data_fn)get_process_data, &data, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data download failed: ");
    goto err1;
  }

  if (file)
  {
    if (!g_output_stream_close(data.stream, NULL, &local_err))
    {
      g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
      goto err1;
    }
  }

  if (file)
    g_object_unref(data.stream);

  // check mac of the downloaded file
  guchar meta_mac_xor_calc[8];
  chunked_cbc_mac_finish8(&data.mac, meta_mac_xor_calc);
  if (memcmp(meta_mac_xor, meta_mac_xor_calc, 8) != 0) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "MAC mismatch");
    goto err1;
  }

  g_free(url);
  http_free(h);
  if (file)
    g_object_unref(file);
  g_free(get_node);

  return TRUE;

err1:
  g_free(url);
  http_free(h);
err0:
  g_free(get_node);
  if (file)
  {
    g_object_unref(data.stream);
    if (remove_file)
      g_file_delete(file, NULL, NULL);
    g_object_unref(file);
  }
  return FALSE;
}

/* increment counter (128-bit int) by n, counter is big-endian */
/* This is very similar to the counter increment by one function
   provided by openssl, which is not part of the public api in
   crypto/modes/ctr128.c.  However, this one allows for increment by
   n, which is more efficient than calling ctr128_inc n times. */
static void ctr128_incn(unsigned char *counter, unsigned int n) {
  unsigned char b=16, c;

  if (n == 0) return;
  do {
    --b;
    c = counter[b];
    c += n % 256;
    n >>= 8;
    counter[b] = c;
    if (c && n == 0) return;
  } while (b);
}

gint mega_session_pread(mega_session* s, const gchar* remote_path, gpointer buf, const size_t count, const off_t offset, GError** err)
{
  struct _get_data data;
  GError* local_err = NULL;
  GFile* file = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->fs_pathmap != NULL, FALSE);
  g_return_val_if_fail(remote_path != NULL, FALSE);
  g_return_val_if_fail(buf != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  memset(&data, 0, sizeof(data));
  data.s = s;

  mega_node* n = mega_session_stat(s, remote_path);
  if (!n)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file not found: %s", remote_path);
    return FALSE;
  }

  data.stream = G_OUTPUT_STREAM(g_memory_output_stream_new (buf, count, NULL, NULL));

  // initialize decrytpion key/state
  guchar aes_key[16], meta_mac_xor[8];
  unpack_node_key(n->key, aes_key, data.iv, meta_mac_xor);
  AES_set_encrypt_key(aes_key, 128, &data.k);
  
  // set decryption state to start decrypting from offset
  data.num = offset % 16;
  ctr128_incn(data.iv, offset / 16);
  AES_encrypt(data.iv, data.ecount, &data.k);
  chunked_cbc_mac_init8(&data.mac, aes_key, data.iv);

  // prepare request
  gchar* get_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, n:%s}]", n->handle);

  if (!get_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  gint64 file_size = s_json_get_member_int(get_node, "s", -1);
  if (file_size < 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
    goto err0;
  }

  gchar* url = s_json_get_member_string(get_node, "g");
  if (!url)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
    goto err0;
  }

  // Only get requested range of bytes
  gchar* tmp_url = g_strdup_printf("%s/%llu-%llu", url, (long long unsigned int)offset, (long long unsigned int)(offset+count-1));
  g_free(url);
  url = tmp_url;

  if (mega_debug & MEGA_DEBUG_API)
    g_print("dlurl = %s\n", url);

  // perform download
  http* h = http_new();
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  if (!http_post_stream_download(h, url, (http_data_fn)get_process_data, &data, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data download failed: ");
    goto err1;
  }

  if (!g_output_stream_close(G_OUTPUT_STREAM(data.stream), NULL, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Can't close downloaded chunk: ");
    goto err1;
  }

  g_object_unref(data.stream);
  g_free(url);
  http_free(h);
  g_free(get_node);

  return count;

err1:
  g_free(url);
  http_free(h);
err0:
  g_free(get_node);
  g_object_unref(data.stream);
  return -1;
}

// }}}
// {{{ mega_session_dl

struct _dl_data
{
  mega_session* s;
  GFileOutputStream* stream;
  AES_KEY k;
  guchar iv[AES_BLOCK_SIZE];
  gint num;
  guchar ecount[AES_BLOCK_SIZE];
  chunked_cbc_mac mac;
};

static gsize dl_process_data(gpointer buffer, gsize size, struct _dl_data* data)
{
  gchar* out_buffer = g_malloc(size);

  AES_ctr128_encrypt(buffer, out_buffer, size, &data->k, data->iv, data->ecount, &data->num);

  chunked_cbc_mac_update(&data->mac, out_buffer, size);

  init_status(data->s, MEGA_STATUS_DATA);
  data->s->status_data.data.size = size;
  data->s->status_data.data.buf = out_buffer;
  if (send_status(data->s)) 
  {
    g_free(out_buffer);
    return 0;
  }

  if (!data->stream)
  {
    g_free(out_buffer);
    return size;
  }

  if (g_output_stream_write_all(G_OUTPUT_STREAM(data->stream), out_buffer, size, NULL, NULL, NULL))
  {
    g_free(out_buffer);
    return size;
  }

  g_free(out_buffer);
  return 0;
}

gboolean mega_session_dl(mega_session* s, const gchar* handle, const gchar* key, const gchar* local_path, GError** err)
{
  struct _dl_data data;
  GError* local_err = NULL;
  GFile *file = NULL, *parent_dir = NULL;
  gboolean remove_file = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(handle != NULL, FALSE);
  g_return_val_if_fail(key != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  memset(&data, 0, sizeof(data));
  data.s = s;

  if (local_path)
  {
    // get dir and filename to download to
    file = g_file_new_for_path(local_path);
    if (g_file_query_exists(file, NULL))
    {
      if (g_file_query_file_type(file, 0, NULL) != G_FILE_TYPE_DIRECTORY)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "File already exists: %s", local_path);
        g_object_unref(file);
        return FALSE;
      }
      else
      {
        parent_dir = file;
        file = NULL;
      }
    }
    else
    {
      parent_dir = g_file_get_parent(file);

      if (g_file_query_file_type(parent_dir, 0, NULL) != G_FILE_TYPE_DIRECTORY)
      {
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't download file into: %s", g_file_get_path(parent_dir));
        g_object_unref(parent_dir);
        return FALSE;
      }
    }
  }

  // prepare request
  gchar* dl_node = api_call(s, 'o', NULL, &local_err, "[{a:g, g:1, ssl:0, p:%s}]", handle);
  if (!dl_node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  // get file size
  gint64 file_size = s_json_get_member_int(dl_node, "s", -1);
  if (file_size < 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine file size");
    goto err0;
  }

  gchar* url = s_json_get_member_string(dl_node, "g");
  if (!url)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't determine download url");
    goto err0;
  }

  gchar* at = s_json_get_member_string(dl_node, "at");
  if (!at)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't get file attributes");
    goto err1;
  }

  // decode node_key
  gsize node_key_len = 0;
  guchar* node_key = base64urldecode(key, &node_key_len);
  if (!node_key || node_key_len != 32)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve file key");
    goto err2;
  }

  // initialize decrytpion key
  guchar aes_key[16], meta_mac_xor[8];
  unpack_node_key(node_key, aes_key, data.iv, meta_mac_xor);

  // decrypt attributes with aes_key
  gchar* node_name = NULL;
  if (!decrypt_node_attrs(at, aes_key, &node_name))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid key");
    goto err2;
  }

  if (!node_name)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't retrieve remote file name");
    goto err2;
  }

  init_status(s, MEGA_STATUS_FILEINFO);
  s->status_data.fileinfo.name = node_name;
  s->status_data.fileinfo.size = file_size;
  if (send_status(s)) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Operation cancelled from status callback");
    g_free(node_name);
    goto err2;
  }

  // check for invalid characters in filename
#ifdef G_OS_WIN32
  if (strpbrk(node_name, "/\\<>:\"|?*") || !strcmp(node_name, ".") || !strcmp(node_name, ".."))
#else
  if (strpbrk(node_name, "/") || !strcmp(node_name, ".") || !strcmp(node_name, "..")) 
#endif
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Remote file name is invalid: '%s'", node_name);
    g_free(node_name);
    goto err2;
  }

  if (local_path)
  {
    if (!file)
      file = g_file_get_child(parent_dir, node_name);
  }

  g_free(node_name);

  if (local_path)
  {
    // open local file for writing
    data.stream = g_file_create(file, 0, NULL, &local_err);
    if (!data.stream)
    {
      gchar* tmp = g_file_get_path(file);
      g_propagate_prefixed_error(err, local_err, "Can't open local file %s for writing: ", tmp);
      g_free(tmp);
      goto err2;
    }
  }

  remove_file = TRUE;

  // initialize decryption and mac calculation
  AES_set_encrypt_key(aes_key, 128, &data.k);
  chunked_cbc_mac_init8(&data.mac, aes_key, data.iv);

  // perform download
  http* h = http_new();
  http_set_progress_callback(h, (http_progress_fn)progress_generic, s);
  if (!http_post_stream_download(h, url, (http_data_fn)dl_process_data, &data, &local_err))
  {
    g_propagate_prefixed_error(err, local_err, "Data download failed: ");
    goto err3;
  }

  if (data.stream)
  {
    if (!g_output_stream_close(G_OUTPUT_STREAM(data.stream), NULL, &local_err))
    {
      g_propagate_prefixed_error(err, local_err, "Can't close downloaded file: ");
      goto err3;
    }

    g_object_unref(data.stream);
  }

  // check mac of the downloaded file
  guchar meta_mac_xor_calc[8];
  chunked_cbc_mac_finish8(&data.mac, meta_mac_xor_calc);
  if (memcmp(meta_mac_xor, meta_mac_xor_calc, 8) != 0) 
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "MAC mismatch");
    goto err3;
  }

  http_free(h);
  g_free(dl_node);
  if (file)
    g_object_unref(file);
  if (parent_dir)
    g_object_unref(parent_dir);
  return TRUE;

err3:
  http_free(h);
  if (data.stream)
    g_object_unref(data.stream);
err2:
  g_free(node_key);
  g_free(at);
err1:
  g_free(url);
err0:
  g_free(dl_node);
  if (file)
  {
    if (remove_file)
      g_file_delete(file, NULL, NULL);
    g_object_unref(file);
  }
  if (parent_dir)
    g_object_unref(parent_dir);
  return FALSE;
}

// }}}

// {{{ mega_node_get_link

gchar* mega_node_get_link(mega_node* n, gboolean include_key)
{
  g_return_val_if_fail(n != NULL, NULL);

  if (n->link)
  {
    if (include_key && n->key)
    {
      gchar* key = mega_node_get_key(n);
      gchar* tmp = g_strdup_printf("https://mega.co.nz/#!%s!%s", n->link, key);
      g_free(key);
      return tmp;
    }

    return g_strdup_printf("https://mega.co.nz/#!%s", n->link);
  }

  return NULL;
}

// }}}
// {{{ mega_node_get_key

gchar* mega_node_get_key(mega_node* n)
{
  g_return_val_if_fail(n != NULL, NULL);

  if (n->key)
    return base64urlencode(n->key, n->key_len);

  return NULL;
}

// }}}

// {{{ mega_session_save

static void save_share_keys(gchar* handle, gchar* key, SJsonGen* gen)
{
  s_json_gen_start_object(gen);
  s_json_gen_member_string(gen, "handle", handle);
  s_json_gen_member_bytes(gen, "key", key, 16);
  s_json_gen_end_object(gen);
}

gboolean mega_session_save(mega_session* s, GError** err)
{
  GError* local_err = NULL;
  GSList* i;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(s->user_email != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  // calculate cache file path
  gchar* un = g_ascii_strdown(s->user_email, -1);
  GChecksum* cs = g_checksum_new(G_CHECKSUM_SHA1);
  g_checksum_update(cs, un, -1);
  gchar* filename = g_strconcat(g_checksum_get_string(cs), ".megatools.cache", NULL);
  gchar* path = g_build_filename(g_get_tmp_dir(), filename, NULL);
  g_free(filename);
  g_checksum_free(cs);
  g_free(un);

  SJsonGen *gen = s_json_gen_new();
  s_json_gen_start_object(gen);

  // serialize session object
  s_json_gen_member_int(gen, "version", CACHE_FORMAT_VERSION);
  s_json_gen_member_int(gen, "last_refresh", s->last_refresh);

  s_json_gen_member_string(gen, "sid", s->sid);
  s_json_gen_member_bytes(gen, "password_key", s->password_key, 16);
  s_json_gen_member_bytes(gen, "master_key", s->master_key, 16);
  s_json_gen_member_rsa_key(gen, "rsa_key", &s->rsa_key);
  s_json_gen_member_string(gen, "user_handle", s->user_handle);
  s_json_gen_member_string(gen, "user_name", s->user_name);
  s_json_gen_member_string(gen, "user_email", s->user_email);

  s_json_gen_member_array(gen, "share_keys");
  g_hash_table_foreach(s->share_keys, (GHFunc)save_share_keys, gen);
  s_json_gen_end_array(gen);

  s_json_gen_member_array(gen, "fs_nodes");
  for (i = s->fs_nodes; i; i = i->next)
  {
    mega_node* n = i->data;

    s_json_gen_start_object(gen);
    s_json_gen_member_string(gen, "name", n->name);
    s_json_gen_member_string(gen, "handle", n->handle);
    s_json_gen_member_string(gen, "parent_handle", n->parent_handle);
    s_json_gen_member_string(gen, "user_handle", n->user_handle);
    s_json_gen_member_string(gen, "su_handle", n->su_handle);
    s_json_gen_member_bytes(gen, "key", n->key, n->key_len);
    s_json_gen_member_int(gen, "type", n->type);
    s_json_gen_member_int(gen, "size", n->size);
    s_json_gen_member_int(gen, "timestamp", n->timestamp);
    s_json_gen_member_string(gen, "link", n->link);
    s_json_gen_end_object(gen);
  }
  s_json_gen_end_array(gen);

  s_json_gen_end_object(gen);
  gchar *cache_data = s_json_gen_done(gen);

  if (mega_debug & MEGA_DEBUG_CACHE)
    print_node(cache_data, "SAVE CACHE: ");

  gchar* tmp = g_strconcat("MEGA", cache_data, NULL);
  gchar* cipher = b64_aes128_cbc_encrypt_str(tmp, s->password_key);
  g_free(tmp);
  g_free(cache_data);

  if (!g_file_set_contents(path, cipher, -1, &local_err))
  {
    g_propagate_error(err, local_err);
    g_free(cipher);
    g_free(path);
    return FALSE;
  }

  g_free(cipher);
  g_free(path);
  return TRUE;
}

// }}}
// {{{ mega_session_load

gboolean mega_session_load(mega_session* s, const gchar* un, const gchar* pw, gint max_age, gchar** last_sid, GError** err)
{
  GError* local_err = NULL;
  gchar* cipher = NULL;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(un != NULL, FALSE);
  g_return_val_if_fail(pw != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_session_close(s);

  // calculate cache file path
  gchar* un_lower = g_ascii_strdown(un, -1);
  GChecksum* cs = g_checksum_new(G_CHECKSUM_SHA1);
  g_checksum_update(cs, un_lower, -1);
  gchar* filename = g_strconcat(g_checksum_get_string(cs), ".megatools.cache", NULL);
  gchar* path = g_build_filename(g_get_tmp_dir(), filename, NULL);
  g_free(filename);
  g_checksum_free(cs);
  g_free(un_lower);

  // load cipher data
  if (!g_file_get_contents(path, &cipher, NULL, &local_err))
  {
    g_propagate_error(err, local_err);
    g_free(path);
    return FALSE;
  }

  g_free(path);

  // calculate password key
  guchar* password_key = make_password_key(pw);
  gsize len = 0;
  gchar* data = b64_aes128_cbc_decrypt(cipher, password_key, &len);
  g_free(password_key);
  g_free(cipher);

  if (!data || len < 4)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupted cache file");
    g_free(data);
    return FALSE;
  }

  if (memcmp(data, "MEGA", 4) != 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Incorrect password");
    g_free(data);
    return FALSE;
  }

  if (!s_json_is_valid(data + 4))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupted cache file");
    g_free(data);
    return FALSE;
  }

  gchar* cache_obj = s_json_get(data + 4);
  g_free(data);

  if (mega_debug & MEGA_DEBUG_CACHE)
    print_node(cache_obj, "LOAD CACHE: ");

  if (s_json_get_type(cache_obj) == S_JSON_TYPE_OBJECT)
  {
    gint64 version = s_json_get_member_int(cache_obj, "version", 0);
    gint64 last_refresh = s_json_get_member_int(cache_obj, "last_refresh", 0);

    if (version != CACHE_FORMAT_VERSION)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Cache version mismatch");
      goto err;
    }

    // return sid value if available
    gchar* sid = s_json_get_member_string(cache_obj, "sid");
    if (last_sid && sid)
      *last_sid = g_strdup(sid);

    // check max_age
    if (max_age > 0)
    {
      if (!last_refresh || ((last_refresh + max_age) < time(NULL)))
      {
        g_free(sid);
        g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Cache timed out");
        goto err;
      }
    }

    // cache is valid, load it
    gsize len;

    s->last_refresh = last_refresh;
    s->sid = sid;
    s->password_key = s_json_get_member_bytes(cache_obj, "password_key", &len);
    s->master_key = s_json_get_member_bytes(cache_obj, "master_key", &len);
    s_json_get_member_rsa_key(cache_obj, "rsa_key", &s->rsa_key);
    s->user_handle = s_json_get_member_string(cache_obj, "user_handle");
    s->user_name = s_json_get_member_string(cache_obj, "user_name");
    s->user_email = s_json_get_member_string(cache_obj, "user_email");

    if (!s->sid || !s->password_key || !s->master_key || !s->user_handle || !s->user_email || !s->rsa_key.p || !s->rsa_key.q || !s->rsa_key.d || !s->rsa_key.u)
    {
      g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Incomplete cache data");
      goto err;
    }

    const gchar* sk_nodes = s_json_get_member(cache_obj, "share_keys");
    if (s_json_get_type(sk_nodes) == S_JSON_TYPE_ARRAY)
    {
      gint i = 0;
      const gchar* sk_node;

      while ((sk_node = s_json_get_element(sk_nodes, i++)))
      {
        gchar* handle = s_json_get_member_string(sk_node, "handle");
        guchar* key = s_json_get_member_bytes(sk_node, "key", &len);
        add_share_key(s, handle, key);
        g_free(key);
        g_free(handle);
      }
    }

    const gchar* fs_nodes = s_json_get_member(cache_obj, "fs_nodes");
    if (s_json_get_type(fs_nodes) == S_JSON_TYPE_ARRAY)
    {
      gint i = 0;
      const gchar* fs_node;

      while ((fs_node = s_json_get_element(fs_nodes, i++)))
      {
        mega_node* n = g_new0(mega_node, 1);

        n->name = s_json_get_member_string(fs_node, "name");
        n->handle = s_json_get_member_string(fs_node, "handle");
        n->parent_handle = s_json_get_member_string(fs_node, "parent_handle");
        n->user_handle = s_json_get_member_string(fs_node, "user_handle");
        n->su_handle = s_json_get_member_string(fs_node, "su_handle");
        n->key = s_json_get_member_bytes(fs_node, "key", &n->key_len);
        n->type = s_json_get_member_int(fs_node, "type", -1);
        n->size = s_json_get_member_int(fs_node, "size", -1);
        n->timestamp = s_json_get_member_int(fs_node, "timestamp", -1);
        n->link = s_json_get_member_string(fs_node, "link");

        s->fs_nodes = g_slist_prepend(s->fs_nodes, n);
      }

      s->fs_nodes = g_slist_reverse(s->fs_nodes);
    }
  }
  else
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Corrupt cache");
    goto err;
  }

  update_pathmap(s);

  g_free(cache_obj);
  return TRUE;

err:
  g_free(cache_obj);
  return FALSE;
}

// }}}

// {{{ mega_session_register

gboolean mega_session_register(mega_session* s, const gchar* email, const gchar* password, const gchar* name, mega_reg_state** state, GError** err)
{
  GError* local_err = NULL;
  gchar* node;
  gboolean status = FALSE;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(email != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);
  g_return_val_if_fail(state != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  // logout
  mega_session_close(s);

  // create new master key
  guchar* master_key = make_random_key();

  // create password key
  guchar* password_key = make_password_key(password);

  // create username hash
  gchar* email_lower = g_ascii_strdown(email, -1);
  gchar* uh = make_username_hash(email_lower, password_key);

  // create ssc (session self challenge) and ts
  guchar* ssc = make_random_key();
  guchar ts_data[32];
  memcpy(ts_data, ssc, 16);
  aes128_encrypt(ts_data + 16, ts_data, 16, master_key);
  g_free(ssc);

  // create anon user - [{"a":"up","k":"cHl8JeeSqgBOiURQL_Dvug","ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}] -> ["-a1DHeWfguY"]
  node = api_call(s, 's', NULL, &local_err, "[{a:up, k:%S, ts:%S}]", b64_aes128_encrypt(master_key, 16, password_key), base64urlencode(ts_data, 32));
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err0;
  }

  gchar* user_handle = s_json_get_string(node);
  g_free(node);

  // login as an anon user - [{"a":"us","user":"-a1DHeWfguY"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"cHl8JeeSqgBOiURQL_Dvug"}]
  node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s}]", user_handle);
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err1;
  }

  // from now on, tsid is used as session ID
  s->sid = s_json_get_member_string(node, "tsid");
  g_free(node);

  // get user info - [{"a":"ug"}] -> [{"u":"-a1DHeWfguY","s":1,"n":0,"k":"cHl8JeeSqgBOiURQL_Dvug","c":0,"ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}]
  node = api_call(s, 'o', NULL, &local_err, "[{a:ug}]");
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err1;
  }

  g_free(node);

  // set user name - [{"a":"up","name":"Bob Brown"}] -> ["-a1DHeWfguY"]
  node = api_call(s, 's', NULL, &local_err, "[{a:up, name:%s}]", name);
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err1;
  }

  g_free(node);

  // request signup link - [{"a":"uc","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ic","n":"Qm9iIEJyb3du","m":"bWVnb3VzQGVtYWlsLmN6"}] -> [0]
  guchar c_data[32] = {0}; // aes(master_key, pw_key) + aes(verify, pw_key)
  memcpy(c_data, master_key, 16);
  RAND_bytes(c_data + 16, 4);
  RAND_bytes(c_data + 16 + 12, 4);

  // this will set new k from the first 16 bytes of c
  node = api_call(s, 'i', NULL, &local_err, "[{a:uc, c:%S, n:%S, m:%S}]", b64_aes128_encrypt(c_data, 32, password_key), base64urlencode(name, strlen(name)), base64urlencode(email, strlen(email)));
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err1;
  }

  g_free(node);

  // save state
  mega_reg_state* st = *state = g_new0(mega_reg_state, 1);
  st->user_handle = user_handle;
  user_handle = NULL;
  memcpy(st->password_key, password_key, 16);
  memcpy(st->challenge, c_data + 16, 16);

  status = TRUE;

err1:
  g_free(user_handle);
err0:
  g_free(uh);
  g_free(email_lower);
  g_free(password_key);
  g_free(master_key);
  return status;
}


// }}}
// {{{ mega_session_register_verify

gboolean mega_session_register_verify(mega_session* s, mega_reg_state* state, const gchar* signup_key, GError** err)
{
  GError* local_err = NULL;
  gboolean status = FALSE;
  gchar* node;

  g_return_val_if_fail(s != NULL, FALSE);
  g_return_val_if_fail(state != NULL, FALSE);
  g_return_val_if_fail(state->user_handle != NULL, FALSE);
  g_return_val_if_fail(signup_key != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  mega_session_close(s);

  // generate RSA key
  rsa_key key;
  memset(&key, 0, sizeof(key));
  if (!rsa_key_gen(&key))
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Can't generate RSA key");
    return FALSE;
  }

  // u_types:
  //   0: not registered (!u.email)
  //   1: not sent confirmation email (!u.c)
  //   2: not yet set RSA key (!u.privk)
  //   3: full account

  // login as an anon user - [{"a":"us","user":"-a1DHeWfguY"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"cHl8JeeSqgBOiURQL_Dvug"}]
  node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s}]", state->user_handle);
  if (!node)
  {
    g_propagate_error(err, local_err);
    return FALSE;
  }

  // from now on, tsid is used as session ID
  s->sid = s_json_get_member_string(node, "tsid");
  g_free(node);

  // send confirmation
  //
  // https://mega.co.nz/#confirmZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg
  //
  // [{"a":"ud","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg"}] 
  //
  // -> [["bWVnb3VzQGVtYWlsLmN6","Qm9iIEJyb3du","-a1DHeWfguY","ZOB7VJrNXFvCzyZBIcdWhg","vmXh0lq2takSMSkCYfXuJw"]]
  //            ^                       ^            ^                    ^                       ^
  //          email                    name        handle       enc(master_key, pwkey)   enc(challenge, pwkey)

  node = api_call(s, 'a', NULL, &local_err, "[{a:ud, c:%s}]", signup_key);
  if (!node)
  {
    g_propagate_error(err, local_err);
    return FALSE;
  }

  gchar** arr = s_json_get_elements(node);
  if (g_strv_length(arr) != 5)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Wrong number of elements in retval from 'ud' (%d)", g_strv_length(arr));
    g_free(arr);
    g_free(node);
    return FALSE;
  }

  gchar* b64_email = s_json_get_string(arr[0]);
  gchar* b64_name = s_json_get_string(arr[1]);
  gchar* b64_master_key = s_json_get_string(arr[3]);
  gchar* b64_challenge = s_json_get_string(arr[4]);

  if (b64_email == NULL || b64_name == NULL || b64_master_key == NULL || b64_challenge == NULL)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid retval type from 'ud'");
    g_free(node);
    goto err0;
  }

  gsize len;
  gchar* email = base64urldecode(b64_email, &len);
  gchar* name = base64urldecode(b64_name, &len);
  guchar* master_key = b64_aes128_decrypt(b64_master_key, state->password_key, NULL);
  guchar* challenge = b64_aes128_decrypt(b64_challenge, state->password_key, NULL);

  g_free(node);

  if (email == NULL || name == NULL || master_key == NULL || challenge == NULL)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid retval type from 'ud'");
    goto err1;
  }

  // check challenge response
  if (memcmp(challenge, state->challenge, 16) != 0)
  {
    g_set_error(err, MEGA_ERROR, MEGA_ERROR_OTHER, "Invalid challenge response");
    g_free(node);
    goto err1;
  }

  // create username hash
  gchar* email_lower = g_ascii_strdown(email, -1);
  gchar* uh = make_username_hash(email_lower, state->password_key);

  // save uh and c
  // [{"uh":"VcWbhpU9cb0","c":"ZOB7VJrNXFvCzyZBIcdWhr5l4dJatrWpEjEpAmH17ieRRWFjWAUAtSqaVQ_TQKltZWdvdXNAZW1haWwuY3oJQm9iIEJyb3duMhVh8n67rBg","a":"up"}] -> ["-a1DHeWfguY"]
  node = api_call(s, 's', NULL, &local_err, "[{a:up, c:%s, uh:%s}]", signup_key, uh);
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err2; 
  }

  g_free(node);

  // relogin using email + uh
  // [{"a":"us","user":"megous@email.cz","uh":"VcWbhpU9cb0"}] -> [{"tsid":"W9fg4kOw8p44KWoWICbgES1hMURIZVdmZ3VZ3et8yi-vkehKMjW83vzjmw","k":"ZOB7VJrNXFvCzyZBIcdWhg"}]
  
  node = api_call(s, 'o', NULL, &local_err, "[{a:us, user:%s, uh:%s}]", email_lower, uh);
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err2; 
  }

  g_free(s->sid);
  s->sid = s_json_get_member_string(node, "tsid");

  g_free(node);

  // set RSA key pair
  // [{"a":"up", "privk":"...", "pubk":"..."}] -> ["-a1DHeWfguY"]
  node = api_call(s, 's', NULL, &local_err, "[{a:up, pubk:%S, privk:%S}]", b64_encode_pubk(&key), b64_aes128_encrypt_privk(master_key, &key));
  if (!node)
  {
    g_propagate_error(err, local_err);
    goto err2; 
  }

  g_free(node);

  //[{"a":"ug"}] -> [{"u":"-a1DHeWfguY","s":1,"email":"megous@email.cz","name":"Bob Brown","k":"ZOB7VJrNXFvCzyZBIcdWhg","c":1,"ts":"W9fg4kOw8p44KWoWICbgEd3rfMovr5HoSjI1vN7845s"}]
  //[{"a":"up","privk":"KSUujv7KB8QYL2At2sWeMPi2DQd_e09FwbR2RwileC9NxYw0MxFTKFj7Yxha__borDmBUacxaWXRCnMnAmMlsyWc8zw_ml9tysYHOsL4cQEzpBJtCCIrhnRjwnQk8JUVK--5fyQRS6G2RiOVdeFjkKQyifmXgBsiAlhHKhzSY0VD6ruR9htGfDsgImim_S-MzuWaHQN8TJkBkSZRAgXy6O2tUh0Bk4aEp8NaEV0GHdV7ec1S1jbR9FzwKB7cNkKxk2nd7wRS9rnl_QPz4MTv84dS6qHxahT0ebU5njC2_IkFLxuVlloyO2UTPRPHa9JHaPa3R2BrEmb-eWMmsZ5icNwJl8PLzuc9YlSI09-IR5rHZLm2uW-V05GI1IHIjw9LGzqli6WL7tzlMVhHrsq-xj70iXjVvOXJ3XhwbbW99S8O-3sQ2gG36fSHUcg0WMSD-8KiD-DhmhfqX8iqg-2YDfXrsYUNhq_VHJF83Zm0itPdRIkgUtBR9MFdASSPe_8uxlEBsCATTHNGIWbH0wiKRo2tEqbUTZCJjXhAyTyMhdjbSdS1ARKNr12YHkLKi12uhIJRO73VJGmjZD8De59cPduGihLGt3ipIKVIxsm-Xy6f9p29BtDHE1go_yacqbW1n8d1anN8WhmG8Q_1PwY1h-opagpd-Nf0geFti_3PI8dY75NPAuDyknv0kgn8OZ4ItzO10-4H3_GgLa5m8zb6usk-eeVCo4lkC4Z2YHHlY4YLRIL7rWC0m_kFcsyvVi1-PVNJ8GauLt9PYmW9hj20yJLwCYkEVSQyM4Yxgh55hSa3La3FnUt3Nls_ImOdcDWtYpB0UKJSKN_IYH4NlD60VwvFUifJndRB_JlJGvqzR4s","pubk":"B_9lGyG4ImN-3idVOARGr6dk-4Nn6VwVYxCTSk1nDvXztCNQ-eFwxIJoS3ykODSH_AjHhst_Loj_erSgX-AUOBAjkh5rQuriA4ciT76tIh_IarC5Yf2Zey8Ao_gLPgaqrLTIWPxDhSAmCLd3pa3X9weAuGK_7eiVxmXU4tK_5j7dyn949C4OMNhxp9vRgZqaOzcjouwKm8xH9nWqXTR7F2WKW2BcXxeBkRnFVJz6cd5IqmJENabhDH1-UDf9eCW7GeD2MHU8xnbJk2fXqnru35nxz9OG6VvVDMzrS6dtQU8mC7xnIut_N6eyMRWsHpm8N1bSxHgz1XWCodnOBHFIJSoJAAUR"}] -> ["-a1DHeWfguY"]

  status = TRUE;

err2:
  g_free(uh);
  g_free(email_lower);
err1:
  g_free(email);
  g_free(name);
  g_free(master_key);
  g_free(challenge);
err0:
  g_free(b64_email);
  g_free(b64_name);
  g_free(b64_master_key);
  g_free(b64_challenge);
  return status;
}

// }}}
