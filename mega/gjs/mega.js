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

function isArray(o) {
	return Object.prototype.toString.apply(o) === '[object Array]';
}

const NodeType = {
	FILE: 0,
	FOLDER: 1,
	ROOT: 2,
	INBOX: 3,
	TRASH: 4,
	NETWORK: 9,
	CONTACT: 8
};

const Node = new Lang.Class({
	Name: 'Node',

	_init: function(session) {
		this.session = session;
	},

	loadData: function(nodeData) {
		this.type = nodeData.t;
		this.handle = nodeData.h;
		this.parent_handle = nodeData.p;
		this.user = nodeData.u;
		this.size = nodeData.s;
		this.mtime = nodeData.ts;

		// laod key
		if (nodeData.k) {
			let matches = nodeData.k.match(/[0-9a-z_-]{8,11}:[0-9a-z_-]{22,45}/ig);
			for (let key in matches) {
				let keyHandle = matches[key].split(':')[0];
				let keyData = matches[key].split(':')[1];
				let decKey;

				if (this.session.getUserHandle() == keyHandle) {
					decKey = this.session.mkey;
				} else {
					decKey = this.session.getShareKey(keyHandle);
				}

				if (decKey) {
					if (this.type == NodeType.FILE) {
						this.key = new Mega.FileKey();
						this.key.load_enc_ubase64(keyData, decKey);
					} else {
						this.key = Mega.AesKey.new_from_enc_ubase64(keyData, decKey);
					}

					if (!this.key.is_loaded()) {
						delete this.key;
					}
				} else {
					return false;
				}
			}
		}

		// decrypt attrs

		if (this.key && nodeData.a) {
			try {
				var attrs = this.key.decrypt_string_cbc(nodeData.a);
			} catch (ex) {
				return false;
			}

			if (attrs.match(/^MEGA\{/)) {
				this.attrs = JSON.parse(attrs.substr(4));
				this.name = this.attrs.n;
			}
		}

		if (this.type == NodeType.TRASH) {
			this.name = "Trash";
		} else if (this.type == NodeType.INBOX) {
			this.name = "Inbox";
		} else if (this.type == NodeType.ROOT) {
			this.name = "Root";
		}

		return true;
	},

	getDownloader: function() {
		if (this.type == NodeType.FILE) {
			return new FileDownloader(this);
		}
		
		return null;
	},

	getUploader: function() {
		if (this.type != NodeType.FILE) {
			return new FileUploader(this);
		}

		return null;
	}
});

const FileDownloader = new Lang.Class({
	Name: 'FileDownloader',

	_init: function(node) {
		this.node = node;
		this.http = new Mega.HttpClient();
	},

	getDownloadLink: function() {
		if (this.link) {
			return this.link;
		}

		let r = this.node.session.api.call({
			a: 'g',
			g: 1,
			ssl: 0,
			n: this.node.handle
		});

		this.size = r.s;
		this.link = r.g;

		return r.g;
	},

	download: function(localPath, from, to) {
		this.http.set_header('Connection', 'close');
		let http_io = this.http.post(this.getDownloadLink() + "/" + (from || 0) + (to ? "-" + to : ""), 0);
		let http_is = http_io.get_input_stream();
		let size = this.http.get_response_length(null);

		let mac = new Mega.ChunkedCbcMac();
		let ctr = new Mega.AesCtrEncryptor();
		ctr.set_key(this.node.key);
		ctr.set_position(from || 0);
		ctr.set_mac(mac, Mega.AesCtrEncryptorDirection.DECRYPT);

		http_is = Gio.ConverterInputStream.new(http_is, ctr);

		let f = Gio.File.new_for_path(localPath);
		if (f.query_exists(null)) {
			f.delete(null);
		}

		let fs = f.create(0, null);
		fs.splice(http_is, 0, null);
		fs.close(null);

		if ((from || 0) == 0 && !to) {
			if (!this.node.key.check_mac(mac)) {
				throw new Error("MAC verification failed!");
			}
		}

		return true;
	}
});

const FileUploader = new Lang.Class({
	Name: 'FileUploader',

	_init: function(node) {
		this.parentNode = node;
		this.http = new Mega.HttpClient();
	},

	upload: function(localPath, remoteName) {
		let session = this.parentNode.session;
		session.api.setDebug(true);

		let f = Gio.File.new_for_path(localPath);
		if (!f.query_exists(null)) {
			throw new Error("File not found " + localPath);
		}

		let is = f.read(null);
		let info = is.query_info("standard::size", null);
		let fileSize = info.get_size();
		let link = this.getUploadLink(fileSize);

		this.http.set_header('Connection', 'close');
		let http_io = this.http.post(link, fileSize);
		let http_os = http_io.get_output_stream();
		let http_is = http_io.get_input_stream();

		let key = new Mega.FileKey();
		let mac = new Mega.ChunkedCbcMac();
		let ctr = new Mega.AesCtrEncryptor();

		key.generate();
		ctr.set_key(key);
		ctr.set_position(0);
		ctr.set_mac(mac, Mega.AesCtrEncryptorDirection.ENCRYPT);

		http_os = new Gio.ConverterOutputStream.new(http_os, ctr);

		http_os.splice(is, 0, null);
		let size = this.http.get_response_length(null);
		let handle = http_is.read_bytes(size, null).toString();
		http_os.close(null);

		if (handle.match(/^-\d+$/)) {
			throw new Error("File upload error " + handle);
		}

		if (!handle.match(/^[a-zA-Z0-9_+/-]{20,50}$/)) {
			throw new Error("File upload error - invalid handle: " + handle);
		}

		key.set_mac(mac);

		let r = session.api.call({
			a: 'p',
			t: this.parentNode.handle,
			n: [{
				h: handle,
				t: 0,
				k: String(key.get_enc_ubase64(session.mkey)),
				a: String(key.encrypt_string_cbc('MEGA' + JSON.stringify({n: remoteName})))
			}]
		});

		if (r.f && r.f[0]) {
			let node = new Node(session);
			if (node.loadData(r.f[0])) {
				session.fs_nodes.push(node);
			}
		}

		return true;
	},

	getUploadLink: function(uploadSize) {
		if (this.link) {
			return this.link;
		}

		let r = this.parentNode.session.api.call({
			a: 'u',
			ssl: 0,
			ms: 0,
			r: 0,
			e: 0,
			s: uploadSize
		});

		this.link = r.p;

		return this.link;
	}
});

const ServerError = {
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
		this.api = new Mega.Api();
		this.api.debug = false;
		this.api.server = "eu.api.mega.co.nz";
	},

	setSessionId: function(sid) {
		this.api.sid = sid;
	},

	getSessionId: function() {
		return this.api.sid;
	},

	setDebug: function(v) {
		this.api.debug = !!v;
	},

	getErrorName: function(code) {
		for (let key in ServerError) {
			if (ServerError[key] == code) {
				return key;
			}
		}

		return 'EUNKNOWN';
	},

	call: function(request) {
		let response = JSON.parse(this.api.call(JSON.stringify([request])))[0];

		if (typeof response == 'object') {
			return response;
		}

		throw new Error("API call error: " + this.getErrorName(response));
	}
});

const Session  = new Lang.Class({
	Name: 'Session',

	_init: function(config) {
		this.api = new API();
		this.api.setDebug(true);
		this.share_keys = {};
		this.fs_nodes = [];
		this.fs_paths = {};
	},

	open: function(username, password, sessionId) {
		// generate password key
		this.pkey = Mega.AesKey.new_from_password(password);

		// check existing session
		if (sessionId) {
			this.api.setSessionId(sessionId);
			if (this.loadUser()) {
				return true;
			}
		}

		let r = this.api.call({
			a: 'us',
			uh: this.pkey.make_username_hash(username),
			user: username.toLowerCase()
		});

		this.mkey = Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
		if (!this.mkey.is_loaded()) {
			return false;
		}

		this.rsa = new Mega.RsaKey();
		if (!this.rsa.load_enc_privk(r.privk, this.mkey)) {
			return false;
		}

		let sid = this.rsa.decrypt_sid(r.csid);
		if (!sid) {
			return false;
		}

		this.api.setSessionId(sid);

		return this.loadUser();
	},

	loadUser: function() {
		let r = this.api.call({
			a: 'ug'
		});

		this.user_handle = r.u;
		this.user_email = r.email;
		this.user_name = r.name;
		this.user_c = r.c;

		this.mkey = Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
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

	loadFS: function() {
		let r = this.api.call({
			a: 'f',
			c: 1,
			r: 1
		});

		this.fs_nodes = [];
		if (r.f) {
			for (let i = 0; i < r.f.length; i++) {
				let nodeData = r.f[i];
				let node = new Node(this);
				if (node.loadData(nodeData)) {
					this.fs_nodes.push(node);
				}
			}
		}

		this.mapPaths();
	},

	getPaths: function() {
		let paths = [];

		for (let path in this.fs_paths) {
			paths.push(path);
		}

		return paths.sort();
	},

	getNode: function(path) {
		return this.fs_paths[path];
	},

	mapPaths: function() {
                let me = this;

		function map(parentHandle, basePath) {
			for (let i = 0; i < me.fs_nodes.length; i++) {
				let n = me.fs_nodes[i];

				if ((n.parent_handle && parentHandle && n.parent_handle == parentHandle) || (!parentHandle && !n.parent_handle)) {
					let path = basePath + "/" + n.name;

					if (me.fs_paths[path]) {
						path += "." + n.handle;
					}

					me.fs_paths[path] = n;
					n.path = path;

					if (n.type != NodeType.FILE) {
						map(n.handle, path);
					}
				}
			}
		}

		map(null, "");
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

	getShareKey: function(handle) {
		return this.share_keys[handle];
	},

	setShareKey: function(handle, key) {
		this.share_keys[handle] = key;
	},

	getUserHandle: function() {
		return this.user_handle;
	},

	save: function() {
		let data = {
			sid: this.api.getSessionId()
		};

		print(JSON.stringify(data));
		print(this.pkey.encrypt_string_cbc(JSON.stringify(data)));
		GLib.file_set_contents("session.dat", this.pkey.encrypt_string_cbc(JSON.stringify(data)));
	},

	load: function(username, password) {
		let data;

		this.pkey = Mega.AesKey.new_from_password(password);

		try {
			data = JSON.parse(this.pkey.decrypt_string_cbc(String(GLib.file_get_contents("session.dat")[1])));
		} catch (ex) {
		}

		this.open(username, password, (data || {}).sid);
	}
});
