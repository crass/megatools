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
 * Mega communication API
 */

const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const Mega = imports.gi.Mega;
const Lang = imports.lang;

/*
const FileDownloader = new Lang.Class({
	Name: 'FileDownloader',

	_init: function(config) {
	}
});

const FileUploader = new Lang.Class({
	Name: 'FileUploader',

	_init: function(config) {
	}
});
*/

const ERRORS = {
	EINTERNAL: -1,
	EARGS: -2,
	EAGAIN: -3,
	ERATELIMIT: -4,
	EFAILED: -5,
	ETOOMANY: -6,
	ERANGE: -7,
	EEXPIRED: -8,

	// FS access errors
	ENOENT: -9,
	ECIRCULAR: -10,
	EACCESS: -11,
	EEXIST: -12,
	EINCOMPLETE: -13,

	// crypto errors
	EKEY: -14,

	// user errors
	ESID: -15,
	EBLOCKED: -16,
	EOVERQUOTA: -17,
	ETEMPUNAVAIL: -18,
	ETOOMANYCONNECTIONS: -19
};

const API = new Lang.Class({
	Name: 'API',

	_init: function(config) {
		this.http = new Mega.HttpClient();
		this.id = 1;
	},

	setSessionId: function(sid) {
		this.sid = sid;
	},

	call: function(request) {
		var requestJson = JSON.stringify([request]);
		print("REQ: " + JSON.stringify([request], false, '\t'));

		var post = this.http.post("https://eu.api.mega.co.nz/cs?id=" + this.id + (this.sid ? "&sid=" + this.sid : ''), requestJson.length);
		var os = post.get_output_stream();
                os.write_all(requestJson, null);

		var is = post.get_input_stream();
		var responseJson = is.read_bytes(1024 * 8, null);

		responseJson = Mega.gbytes_to_string(responseJson);

		var response = JSON.parse(responseJson);
		print("RES: " + JSON.stringify(response, false, '\t'));
		if (Array.isArray(response)) {
			return response[0];
		}

		throw new Error("Server returned error " + response);
	}
});

Array.isArray = function(o) {
	return Object.prototype.toString.apply(o) === '[object Array]';
};

const Session  = new Lang.Class({
	Name: 'Session',

	_init: function(config) {
		this.api = new API();
	},

	open: function(username, password, sessionId) {
		// generate password key
		this.pkey = new Mega.AesKey();
		this.pkey.generate_from_password(password);

		// check existing session
		if (sessionId) {
			this.api.setSessionId(sessionId);
			if (this.loadUser()) {
				return true;
			}
		}

		var r = this.api.call({
			a: 'us',
			uh: this.pkey.make_username_hash(username),
			user: username.toLowerCase()
		});

		this.mkey = new Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
		if (!this.mkey.is_loaded()) {
			return false;
		}

		this.rsa = new Mega.RsaKey();
		if (!this.rsa.load_enc_privk(r.privk, this.mkey)) {
			return false;
		}

		var sid = this.rsa.decrypt_sid(r.csid);
		if (!sid) {
			return false;
		}

		this.api.setSessionId(sid);

		return this.loadUser();
	},

	loadUser: function() {
		var r = this.api.call({
			a: 'ug'
		});

		this.user_handle = r.u;
		this.user_email = r.email;
		this.user_name = r.name;
		this.user_c = r.c;

		this.mkey = new Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
		if (!this.mkey.is_loaded()) {
			return false;
		}

		if (!this.rsa) {
			this.rsa = new Mega.RsaKey();
		}

		if (!this.rsa.load_enc_privk(r.privk, this.mkey)) {
			return false;
		}

		if (!this.rsa.load_pubk(r.pubk, this.mkey)) {
			return false;
		}

		return true;
	},

	close: function() {
		this.user_handle = null;
		this.user_email = null;
		this.user_name = null;
		this.user_c = null;
		this.rsa = null;
		this.mkey = null;
		this.pkey = null;
		this.api.setSessionId(null);
	},

	getSessionId: function() {
		return this.api.sid;
	},

	save: function() {
	},

	load: function(username, password) {
	}
});
