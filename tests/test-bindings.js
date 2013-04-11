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

const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const Mega = imports.gi.Mega;
const Mainloop = imports.mainloop;
const Lang = imports.lang;

function hex(v) {
	return Mega.format_hex(v, Mega.HexFormat.PACKED);
}

function assert(name, cond) {
	if (!cond) {
		throw new Error(name);
	}
}

function assert_eq(name, a, b) {
	assert(name + ': ' + String(a) + ' == ' + String(b), a == b);
}

function assert_eq_bytes(name, a, b) {
	assert(name + ': ' + hex(a) + ' == ' + hex(b), hex(a) == hex(b));
}

function run(test) {
	try {
		test();
	} catch (ex) {
		print("FAIL: " + ex.message);
	}
}

function test_utils() {
	var DATA = [0, 1, 2, 3];

	var DATA_FMT_PACKED = Mega.format_hex(DATA, Mega.HexFormat.PACKED);
	var DATA_FMT_C = Mega.format_hex(DATA, Mega.HexFormat.C);
	var DATA_FMT_STRING = Mega.format_hex(DATA, Mega.HexFormat.STRING);

	assert_eq("fmt packed", DATA_FMT_PACKED, "00010203");
	assert_eq("fmt c", DATA_FMT_C, "0x00 0x01 0x02 0x03");
	assert_eq("fmt string", DATA_FMT_STRING, "\"\\x00\\x01\\x02\\x03\"");

	var ENC_DEC_DATA = Mega.base64urldecode(Mega.base64urlencode(DATA));
	assert_eq_bytes("enc-dec ubase64", ENC_DEC_DATA, DATA);

	var KEY_UBASE64 = "HVV7qVaNBVR2dmeQKAoLxg";
	var KEY_HEX = "1D557BA9568D055476766790280A0BC6";
	assert_eq("ubase64 dec key", hex(Mega.base64urldecode(KEY_UBASE64)), KEY_HEX);
}

function test_aes() {
	var PASSWORD = "qwe";
	var PASSWORD_KEY = "b-9n_tUR0KApHfV6HmLcvg";
	var PASSWORD_HEX = "6FEF67FED511D0A0291DF57A1E62DCBE";

	var pkey = new Mega.AesKey.new_from_password("qwe");
	var mkey = new Mega.AesKey.new_generated();

	assert_eq_bytes("pkey get_ubase64 eq get_binary", Mega.base64urldecode(pkey.get_ubase64()), pkey.get_binary());
	assert_eq_bytes("pkey get_enc_ubase64 eq get_enc_binary", Mega.base64urldecode(pkey.get_enc_ubase64(mkey)), pkey.get_enc_binary(mkey));

	var pkey2 = new Mega.AesKey.new_from_enc_ubase64(pkey.get_enc_ubase64(mkey), mkey);
	assert_eq_bytes("pkey == pkey2", pkey.get_binary(), pkey2.get_binary());

	var pkey3 = new Mega.AesKey.new_from_ubase64(pkey.get_ubase64());
	assert_eq_bytes("pkey == pkey3", pkey.get_binary(), pkey3.get_binary());

	var pkey4 = new Mega.AesKey.new_from_enc_binary(pkey.get_enc_binary(mkey), mkey);
	assert_eq_bytes("pkey == pkey4", pkey.get_binary(), pkey4.get_binary());

	var pkey5 = new Mega.AesKey.new_from_binary(pkey.get_binary());
	assert_eq_bytes("pkey == pkey5", pkey.get_binary(), pkey5.get_binary());

	// encrypt/decrypt
	var DATA = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
	var CIPHER = pkey.encrypt(DATA);
	var CIPHER_SHOULD_BE = "dUDHWjxmWDbmtW5DBL1UMHVAx1o8Zlg25rVuQwS9VDA";
	var DATA_DEC = Mega.gbytes_to_string(pkey.decrypt(CIPHER));

	assert_eq_bytes("enc/dec data", DATA, DATA_DEC);
	assert_eq("enc cipher", CIPHER, CIPHER_SHOULD_BE);

	// encrypt_cbc/decrypt_cbc

	var CIPHER_CBC_SHOULD_BE = "dUDHWjxmWDbmtW5DBL1UMMY2CynNH_XJ-XaQA0LKb3k";
	var CIPHER_CBC = pkey.encrypt_cbc(DATA);
	var DATA_CBC_DEC = Mega.gbytes_to_string(pkey.decrypt_cbc(CIPHER_CBC));

	assert_eq_bytes("cbc enc/dec data", DATA, DATA_CBC_DEC);
	assert_eq("cbc enc cipher", CIPHER_CBC, CIPHER_CBC_SHOULD_BE);

	var STRING = "test string";
	var STRING_CIPHER = pkey.encrypt_string_cbc(STRING);
	var STRING_DEC = Mega.gbytes_to_string(pkey.decrypt_cbc(STRING_CIPHER));

	assert_eq("string cbc", STRING, STRING_DEC);
}

function test_rsa() {
	var MY_MASTER_KEY = "HVV7qVaNBVR2dmeQKAoLxg";
	var MY_PRIVK_ENC = "NsfinhwepaXc1T_3-oChHBjJe1QyrjN3BU3sKpmVKZoU63qYnItlT5jbyWi6PDtJ0rBI19J2EFmPFBns_HMb3SH-WzsuTttaxYqAILFsfrxOkyzsQ4qaAmb2iU8dee69z6GIVfCFFYzoI5661GzzVd-J-0ZZwrWoVEvq9Nwv8N3lP7t8Fb7GSgWUtov2V7IOu4KeIX5K_-ZMpwL8QWJOQUt89iL3ZTJnfQc58FPs-atI8Ofsx4TKDIC2TldJ2YXBs44RK_bQR231Ra42bGakzXGBM_JRuM0wkBMF4xYCI1ej6szxKYzdn-78571dDEQ8qXaVYt847DI_-xtcoonywwsDo5Aw_iDyEHyOL2PxYeIGZosx5Y1_LyjdKRM92l2MDjs0ettTK_sXJcdlnEq0q1QYPi3BjOXh4ntms35fQPZqNxf8V9QHAi5v1R3j-Ht0idzN4zPUWPLQn99XHEm5fOT-KGO4JYtQN1UJuqj-zNRr-s_AgxVamXDdt7JUhs3NZz-b3Kv-oL83___r3zMdscDg0qjkU9QVVcpZZCGkFTF3B2MRnjJmK7_RgxTxswnUqupbguWr2e5_emlmArxNnHDZoKYJtHFt9481eeefStqAvUreelkPDVBkkQ77wehDl1ne6-iJUq-spCroYZi8izQBB5F0FfC7lN4mN17pxtaQKia1DHbI0-UEe0OluPpkC-zMS3NPQx3FLpQLYzWpoIC2B9K4RFI5pZ-6C1iPc5QtO6NBsPzf21zlnQtqWvyuEudi7spzpkgylmGxqjRcwdcZMJUU3Ei_BwHu6ERxuAnrnhyE6nxOwL767gpBwxUPvZht9eEgm5HHFr1tffvTjCwp1ZTPn-J5Y-9LTvQP8Gc";
	var MY_PUBK = "B_9TemqO9e4xtP_DyNKmyZJZtRP_nohGTVlF_xYomk1u64jkjpYsQv5sWLt_tl1XQIjZkzg2Q3MyX8e1j9m3429IcvEU6x4cjx-0SkbHKJblQxU_rZIW-BtMXxUt4LGu265XaJCjY_RoexYg5060PuMID59yy1xq6z7NEuitPujiLG1gPYeeFrUvYONYqCJxmmceFuwYdCWBh2zVIJDHIPKJRpIs43K264NLCDK4UtEnAO1HcGox1XqNVNMKiSpeCyK9TV9MRGSvzSQ0Uj1NRUHE8Y7uWk2jgLWcUoiPdCZnfo1HvTvxejs4-DC4E6j_Z3FbS8vJt5Kg1MJm9YXK4v__AAUR";
	var MY_CSID = "CAAEtLYp0vnRpXhEH3QmIj-Ul1LJvVmZgC3_cEvrSYSbhgnSnAKZ_9j8cVSlD76dfcyWfhCmjTQBlz0jxR_c6Y6sFKD1-x2jqhwnhb2l53voNcc9bO4H2B4zxSZFoul2yT5MK2flmbbr184iUcC9wIkU28sV2Bs8HmhpJsgh_N_EVnKjI4Mlz5izeYagStLg_qPEYuQkymnF_vV6IRAD8kJLscgrsBTQdzABwMuVJoQqv-m7R_ftDW4wHEr-rkcfDhO_jvbp2Vr5ofWF_6gGP0KaX6_A6L6-o8pQDX_XqodpS1mx1ONviQdqBd0CsjdE4j36YJy3-bdeo1MFz7dlUHCq";
	var MY_SID = "bmXSdJbAQOxUC7wJMdDZS1h6MnRXV0I1RG1vUJwPQ8ZpSRhysTyTsvPVMg";

	var mk = new Mega.AesKey.new_from_ubase64(MY_MASTER_KEY);
	var rk = new Mega.RsaKey();

	assert('rsa/load enc privk', rk.load_enc_privk(MY_PRIVK_ENC, mk));
	assert('rsa/load pubk', rk.load_pubk(MY_PUBK));

	var DEC_SID = rk.decrypt_sid(MY_CSID);
	assert_eq("rsa/sid dec", DEC_SID, MY_SID);

	assert_eq("rsa/pubk get", rk.get_pubk(), MY_PUBK);
	assert_eq("rsa/privk get", rk.get_enc_privk(mk).substr(0, MY_PRIVK_ENC.length - 32), MY_PRIVK_ENC.substr(0, MY_PRIVK_ENC.length - 32));

	var PLAINTEXT = "message";
	var CIPHER = rk.encrypt(PLAINTEXT);
	var PLAINTEXT_DEC = Mega.gbytes_to_string(rk.decrypt(CIPHER));

	assert_eq("rsa/enc dec", hex(PLAINTEXT), hex(PLAINTEXT_DEC).substr(0, PLAINTEXT.length * 2));
}

run(test_utils);
run(test_aes);
run(test_rsa);
