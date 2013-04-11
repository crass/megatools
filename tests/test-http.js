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

function test_post_simple() {
	var http = new Mega.HttpClient();
	http.set_header('X-Client', 'LibMEGA 1.0');
	http.set_content_type('application/json');

	var DATA = http.post_simple("http://localhost:2000/test.php?action=json", "");
	print(DATA.str);

	http.set_header('Connection', 'close');
	DATA = http.post_simple("http://localhost:2000/test.php?action=json", "qwe");
	print(DATA.str);

	http.close(true, null);
}

function test_post() {
	var http = new Mega.HttpClient();

	var REQUEST = JSON.stringify({a: 'p', b: 'data'});

	var post = http.post("http://localhost:2000/test.php?action=json", REQUEST.length);

	var os = post.get_output_stream();
	os.write_all(REQUEST, null);

	var is = post.get_input_stream();
	print(http.get_response_length(null));
	var RESPONSE = Mega.gbytes_to_string(is.read_bytes(http.get_response_length(null), null));

	print(RESPONSE);
}

try { test_post_simple(); } catch(ex) { print("ERROR[" + ex.domain + ":" + ex.code + "]: " + ex.message); }
try { test_post(); } catch(ex) { print("ERROR[" + ex.domain + ":" + ex.code + "]: " + ex.message); }

/*

let http = new Mega.HttpClient();

let f = new Gio.File.new_for_path("data.dat");
if (f.query_exists(null)) {
	f.delete(null);
}
let fstream = f.create(0, null);

let CHUNK_SIZE = 128 * 1024;

for (var chunk = 0; chunk < 100; chunk++)
{
	try {
		let post = http.post("http://localhost:2000/test.php?off=" + (chunk * CHUNK_SIZE) + "&len=" + CHUNK_SIZE, 0);
		let stream = post.get_input_stream();
		let rem_bytes = CHUNK_SIZE;

		while (rem_bytes > 0) {
			let data = stream.read_bytes(rem_bytes, null);
			rem_bytes -= data.get_size();

			fstream.write_bytes(data, null);
		}

		fstream.flush(null);
	} catch (ex) {
		print("ERROR: " + ex.message);
		break;
	}
}

fstream.close(null);


function test_http() {
}
*/
