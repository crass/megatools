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

const gchar* KEY_NULL = "";
const gchar* KEY_INVALID = "*&%@&@*@!&#";

const gchar* MY_MASTER_KEY = "HVV7qVaNBVR2dmeQKAoLxg";
const gchar* MY_PRIVK_ENC = "NsfinhwepaXc1T_3-oChHBjJe1QyrjN3BU3sKpmVKZoU63qYnItlT5jbyWi6PDtJ0rBI19J2EFmPFBns_HMb3SH-WzsuTttaxYqAILFsfrxOkyzsQ4qaAmb2iU8dee69z6GIVfCFFYzoI5661GzzVd-J-0ZZwrWoVEvq9Nwv8N3lP7t8Fb7GSgWUtov2V7IOu4KeIX5K_-ZMpwL8QWJOQUt89iL3ZTJnfQc58FPs-atI8Ofsx4TKDIC2TldJ2YXBs44RK_bQR231Ra42bGakzXGBM_JRuM0wkBMF4xYCI1ej6szxKYzdn-78571dDEQ8qXaVYt847DI_-xtcoonywwsDo5Aw_iDyEHyOL2PxYeIGZosx5Y1_LyjdKRM92l2MDjs0ettTK_sXJcdlnEq0q1QYPi3BjOXh4ntms35fQPZqNxf8V9QHAi5v1R3j-Ht0idzN4zPUWPLQn99XHEm5fOT-KGO4JYtQN1UJuqj-zNRr-s_AgxVamXDdt7JUhs3NZz-b3Kv-oL83___r3zMdscDg0qjkU9QVVcpZZCGkFTF3B2MRnjJmK7_RgxTxswnUqupbguWr2e5_emlmArxNnHDZoKYJtHFt9481eeefStqAvUreelkPDVBkkQ77wehDl1ne6-iJUq-spCroYZi8izQBB5F0FfC7lN4mN17pxtaQKia1DHbI0-UEe0OluPpkC-zMS3NPQx3FLpQLYzWpoIC2B9K4RFI5pZ-6C1iPc5QtO6NBsPzf21zlnQtqWvyuEudi7spzpkgylmGxqjRcwdcZMJUU3Ei_BwHu6ERxuAnrnhyE6nxOwL767gpBwxUPvZht9eEgm5HHFr1tffvTjCwp1ZTPn-J5Y-9LTvQP8Gc";
const gchar* MY_PUBK = "B_9TemqO9e4xtP_DyNKmyZJZtRP_nohGTVlF_xYomk1u64jkjpYsQv5sWLt_tl1XQIjZkzg2Q3MyX8e1j9m3429IcvEU6x4cjx-0SkbHKJblQxU_rZIW-BtMXxUt4LGu265XaJCjY_RoexYg5060PuMID59yy1xq6z7NEuitPujiLG1gPYeeFrUvYONYqCJxmmceFuwYdCWBh2zVIJDHIPKJRpIs43K264NLCDK4UtEnAO1HcGox1XqNVNMKiSpeCyK9TV9MRGSvzSQ0Uj1NRUHE8Y7uWk2jgLWcUoiPdCZnfo1HvTvxejs4-DC4E6j_Z3FbS8vJt5Kg1MJm9YXK4v__AAUR";
const gchar* MY_CSID = "CAAEtLYp0vnRpXhEH3QmIj-Ul1LJvVmZgC3_cEvrSYSbhgnSnAKZ_9j8cVSlD76dfcyWfhCmjTQBlz0jxR_c6Y6sFKD1-x2jqhwnhb2l53voNcc9bO4H2B4zxSZFoul2yT5MK2flmbbr184iUcC9wIkU28sV2Bs8HmhpJsgh_N_EVnKjI4Mlz5izeYagStLg_qPEYuQkymnF_vV6IRAD8kJLscgrsBTQdzABwMuVJoQqv-m7R_ftDW4wHEr-rkcfDhO_jvbp2Vr5ofWF_6gGP0KaX6_A6L6-o8pQDX_XqodpS1mx1ONviQdqBd0CsjdE4j36YJy3-bdeo1MFz7dlUHCq";
const gchar* MY_SID = "bmXSdJbAQOxUC7wJMdDZS1h6MnRXV0I1RG1vUJwPQ8ZpSRhysTyTsvPVMg";

gchar* trim_last_block(const gchar* str)
{
  g_assert(str != NULL);
  return g_strndup(str, strlen(str) - 22);
}

void test_rsa(void)
{
  // my keys
  MegaAesKey* mk = mega_aes_key_new_from_ubase64(MY_MASTER_KEY);
  MegaRsaKey* rk = mega_rsa_key_new();
  
  g_assert(mega_rsa_key_load_enc_privk(rk, MY_PRIVK_ENC, mk));
  g_assert(mega_rsa_key_load_pubk(rk, MY_PUBK));

  GBytes* sid_bytes = mega_rsa_key_decrypt(rk, MY_CSID);
  g_assert_cmpuint(g_bytes_get_size(sid_bytes), >=, 43);
  gchar* sid = mega_base64urlencode(g_bytes_get_data(sid_bytes, NULL), 43);
  g_assert_cmpstr(sid, ==, MY_SID);

  g_assert_cmpstr(mega_rsa_key_get_pubk(rk), ==, MY_PUBK);
  // last block can be different, because it's random padded
  g_assert_cmpstr(trim_last_block(mega_rsa_key_get_enc_privk(rk, mk)), ==, trim_last_block(MY_PRIVK_ENC));

  // test encryption

  guchar plain[16] = {0xff};
  gchar* cipher = mega_rsa_key_encrypt(rk, plain, 16);
  GBytes* plain_bytes = mega_rsa_key_decrypt(rk, cipher);
  g_assert(plain_bytes != NULL);
  g_assert_cmpuint(g_bytes_get_size(plain_bytes), >, 16);
  g_assert(memcmp(g_bytes_get_data(plain_bytes, NULL), plain, 16) == 0);

  // Mega BUG: Plaintext can't start with zero!
  memset(plain, 0, 16);
  cipher = mega_rsa_key_encrypt(rk, plain, 16);
  plain_bytes = mega_rsa_key_decrypt(rk, cipher);
  g_assert(plain_bytes != NULL);
  g_assert_cmpuint(g_bytes_get_size(plain_bytes), >, 16);
  g_assert(memcmp(g_bytes_get_data(plain_bytes, NULL), plain, 16) == 0);

  // generate key

  g_assert(mega_rsa_key_generate(rk));
  gchar* privk1 = mega_rsa_key_get_enc_privk(rk, mk);
  gchar* pubk1 = mega_rsa_key_get_pubk(rk);

  g_assert(mega_rsa_key_generate(rk));
  gchar* privk2 = mega_rsa_key_get_enc_privk(rk, mk);
  gchar* pubk2 = mega_rsa_key_get_pubk(rk);

  g_assert_cmpstr(pubk1, !=, pubk2);
  // last block can be different, because it's random padded
  g_assert_cmpstr(trim_last_block(privk1), !=, trim_last_block(privk2));

  // INVALID USES

  g_assert(!mega_rsa_key_load_enc_privk(rk, MY_CSID, mk));
  g_assert(!mega_rsa_key_load_pubk(rk, MY_CSID));
  g_assert(!mega_rsa_key_load_enc_privk(rk, KEY_INVALID, mk));
  g_assert(!mega_rsa_key_load_pubk(rk, KEY_INVALID));
  g_assert(!mega_rsa_key_load_enc_privk(rk, KEY_NULL, mk));
  g_assert(!mega_rsa_key_load_pubk(rk, KEY_NULL));
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

  g_test_add_func("/rsa", test_rsa);

  return g_test_run();
}
