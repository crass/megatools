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

function handleRequest(method, resource, body, headers) {
	print(method + " " + resource + "\n" + body);

	return "HELLO: " + body;
}

function handleConnection(service, conn) {
	conn.close(null);
	return;
	try {
		var i = new Gio.DataInputStream({"base-stream": conn.get_input_stream()});
		i.set_newline_type(Gio.DataStreamNewlineType.ANY);
		var o = conn.get_output_stream();

		while (true) {
			//print("Connection from: " + conn.get_remote_address().get_address().to_string());

			var status_line = null;
			var headers = {};
			while (true) {
				var ln = String(i.read_line(null)[0]);

				if (!status_line) {
					status_line = ln;
					continue;
				}

				if (!ln) {
					break;
				}

				var m = ln.match(/^([a-z0-9-]+):\s*(.*)\s*$/i);
				if (m) {
					headers[m[1].toLowerCase()] = m[2];
				}
			}

			var s = status_line.match(/^(POST|GET|DELETE|PUT|OPTIONS) ([^ ]+) HTTP\/\d\.\d$/);
			if (!s) {
				throw new Error("Invalid status line: " + status_line);
			}

			if (typeof headers['content-length'] == 'undefined') {
				throw new Error("Client didn't send content-length");
			}

			var content_length = Number(headers['content-length']);
			var request_body;
			if (content_length > 0) {
				request_body = i.read_bytes(content_length, null);
			}

			var response = handleRequest(s[1], s[2], request_body ? Mega.gbytes_to_string(request_body) : "", headers);

			o.write_all("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + response.length + "\r\n\r\n", null);
			//o.write_all("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: " + response.length + "\r\n\r\n", null);
			o.write_all(response, null);

			if (headers['connection'] == 'close' || true) {
				break;
			}
		}

		conn.close(null);
	} catch(ex) {
		print("server[" + ex.lineNumber + "]: " + ex.message);
		conn.close(null);
	}
}

var service = new Gio.SocketService();
service.add_inet_port(2000, null);
service.connect("incoming", handleConnection);
service.start();

print("HTTP server listening on localhost:2000");
Mainloop.run('server');
