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

#include <mega/mega.h>
#include <string.h>

const guchar* KEY_BINARY = "1234567812345678";
const gchar* KEY_UBASE64 = "MTIzNDU2NzgxMjM0NTY3OA";
const gchar* KEY_LONG = "31t2-rTNQoh5bJ-pYJ3DEAJabe";
const gchar* KEY_SHORT = "31t2-rTNQoh-pYJ";
const gchar* KEY_NULL = "";
const gchar* KEY_INVALID = "*&%@&@*@!&#";

const gchar* PASSWORD = "qwe";
const gchar* PASSWORD_BUG = "123456789.123456";
const gchar* PASSWORD_KEY = "b-9n_tUR0KApHfV6HmLcvg";
const gchar* ENC_MASTER_KEY = "ZRnpzigY09qdbk4XR_MHCw";
const gchar* DEC_MASTER_KEY = "7YfLv-KQ5n79vPsZOmJMKw";

const gchar* USERNAME = "bob@email.com";
const gchar* USERNAME_UC = "BOB@email.com";
const gchar* UNHASH = "Bg3XIXKvoco";

void test_aes_construction(void)
{
  MegaAesKey *k, *ek;

  // VALID USES:
  
  // create empty key, check that it is not laoded
  k = mega_aes_key_new();
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);

  // create key from UBase64
  k = mega_aes_key_new_from_ubase64(KEY_UBASE64);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(mega_aes_key_is_loaded(k));
  g_assert_cmpstr(KEY_UBASE64, ==, mega_aes_key_get_ubase64(k));
  g_object_unref(k);

  // create key from Binary data (use as dec_key below)
  ek = mega_aes_key_new_from_binary(KEY_BINARY);
  g_assert(MEGA_IS_AES_KEY(ek));
  g_assert(mega_aes_key_is_loaded(ek));
  g_assert(memcmp(KEY_BINARY, mega_aes_key_get_binary(ek), 16) == 0);
  g_assert_cmpstr(KEY_UBASE64, ==, mega_aes_key_get_ubase64(ek));

  // create key from encrypted UBase64
  k = mega_aes_key_new_from_enc_ubase64(KEY_UBASE64, ek);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(mega_aes_key_is_loaded(k));
  g_assert_cmpstr(KEY_UBASE64, ==, mega_aes_key_get_enc_ubase64(k, ek));
  g_object_unref(k);

  // create key from encrypted Binary data
  k = mega_aes_key_new_from_enc_binary(KEY_BINARY, ek);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(mega_aes_key_is_loaded(k));
  g_assert(memcmp(KEY_BINARY, mega_aes_key_get_enc_binary(k, ek), 16) == 0);
  g_object_unref(k);

  g_object_unref(ek);

  // INVALID USES

  k = mega_aes_key_new_from_ubase64(KEY_LONG);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);

  k = mega_aes_key_new_from_ubase64(KEY_SHORT);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);

  k = mega_aes_key_new_from_ubase64(KEY_INVALID);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);

  k = mega_aes_key_new_from_ubase64(KEY_NULL);
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);

  g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "*data != NULL*");
  k = mega_aes_key_new_from_ubase64(NULL);
  g_test_assert_expected_messages();
  g_assert(MEGA_IS_AES_KEY(k));
  g_assert(!mega_aes_key_is_loaded(k));
  g_object_unref(k);
}

void test_aes_generate(void)
{
  MegaAesKey *pk, *mk, *k1, *k2;

  // create and verify key from password
  pk = mega_aes_key_new_from_password(PASSWORD);
  g_assert(mega_aes_key_is_loaded(pk));
  g_assert_cmpstr(PASSWORD_KEY, ==, mega_aes_key_get_ubase64(pk));

  // create master key from encrypted UBase64, and verify against decrypted
  mk = mega_aes_key_new_from_enc_ubase64(ENC_MASTER_KEY, pk);
  g_assert(mega_aes_key_is_loaded(mk));
  g_assert_cmpstr(DEC_MASTER_KEY, ==, mega_aes_key_get_ubase64(mk));
  g_assert_cmpstr(ENC_MASTER_KEY, ==, mega_aes_key_get_enc_ubase64(mk, pk));
  g_object_unref(mk);
  g_object_unref(pk);

  // create random keys and compare
  k1 = mega_aes_key_new_generated();
  k2 = mega_aes_key_new_generated();
  g_assert(mega_aes_key_is_loaded(k1));
  g_assert(mega_aes_key_is_loaded(k2));
  g_assert_cmpstr(mega_aes_key_get_ubase64(k1), !=, mega_aes_key_get_ubase64(k2));
  g_object_unref(k1);
  g_object_unref(k2);

  // check if long passwords work
  pk = mega_aes_key_new_from_password(PASSWORD_BUG);
  g_assert(mega_aes_key_is_loaded(pk));
}

void test_aes_encrypt(void)
{
  MegaAesKey* k = mega_aes_key_new_from_binary(KEY_BINARY);
  g_assert(mega_aes_key_is_loaded(k));

  guchar plain[64] = {0}, cipher[64] = {0}, plain_dec[64] = {0};

  mega_aes_key_encrypt_raw(k, plain, cipher, 64);
  mega_aes_key_decrypt_raw(k, cipher, plain_dec, 64);

  g_assert(memcmp(plain, plain_dec, 64) == 0);
  g_assert(memcmp(plain, cipher, 64) != 0);

  // VALID use of UBase64 funcs
  gchar* cipher_ubase64 = mega_aes_key_encrypt(k, plain, 16);
  g_assert_cmpstr(cipher_ubase64, ==, "muj9ArNAKIoOe7_w8LpU1g");
  GBytes* plain_bytes = mega_aes_key_decrypt(k, cipher_ubase64);
  g_assert_cmpuint(g_bytes_get_size(plain_bytes), ==, 16);
  g_assert(memcmp(g_bytes_get_data(plain_bytes, NULL), plain, 16) == 0);

  // INVALID use of UBase64 funcs
  g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "*(len % 16) == 0*failed*");
  gchar* non_multiple_of_16 = mega_aes_key_encrypt(k, plain, 18);
  g_test_assert_expected_messages();
  g_assert(non_multiple_of_16 == NULL);
  
  g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, "*len > 0*failed*");
  gchar* zero_length = mega_aes_key_encrypt(k, plain, 0);
  g_test_assert_expected_messages();
  g_assert(zero_length == NULL);

  GBytes* invalid_key_ubase64 = mega_aes_key_decrypt(k, KEY_INVALID);
  g_assert(invalid_key_ubase64 == NULL);

  GBytes* null_key_ubase64 = mega_aes_key_decrypt(k, KEY_NULL);
  g_assert(null_key_ubase64 == NULL);
}

void test_aes_cbc(void)
{
  /*
gchar*                  mega_aes_key_encrypt_cbc        (MegaAesKey* aes_key, const guchar* plain, gsize len);
gchar*                  mega_aes_key_encrypt_string_cbc (MegaAesKey* aes_key, const gchar* str);
GBytes*                 mega_aes_key_decrypt_cbc        (MegaAesKey* aes_key, const gchar* cipher);
*/
}

void test_aes_ctr(void)
{
  /*
void                    mega_aes_key_setup_ctr          (MegaAesKey* aes_key, guchar* nonce, guint64 position);
void                    mega_aes_key_encrypt_ctr        (MegaAesKey* aes_key, guchar* from, guchar* to, gsize len);
*/
}

void test_aes_un_hash(void)
{
  MegaAesKey* pk = mega_aes_key_new();
  mega_aes_key_generate_from_password(pk, PASSWORD);

  g_assert_cmpstr(mega_aes_key_make_username_hash(pk, USERNAME), ==, UNHASH);
  g_assert_cmpstr(mega_aes_key_make_username_hash(pk, USERNAME_UC), ==, UNHASH);
}

int main(int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2, 32, 0)
  if (!g_thread_supported())
    g_thread_init(NULL);
#endif

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/aes/construction", test_aes_construction);
  g_test_add_func("/aes/generate", test_aes_generate);
  g_test_add_func("/aes/encrypt", test_aes_encrypt);
  g_test_add_func("/aes/cbc", test_aes_cbc);
  g_test_add_func("/aes/ctr", test_aes_ctr);
  g_test_add_func("/aes/un-hash", test_aes_un_hash);

  return g_test_run();
}
