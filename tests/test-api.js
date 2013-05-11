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

//const Gio = imports.gi.Gio;
//const GLib = imports.gi.GLib;
//const Lang = imports.lang;
//const MegaCore = imports.gi.Mega;
const Mega = imports.mega;
const Config = imports.config;

var s = new Mega.Session();
//s.open(Config.USERNAME, Config.PASSWORD);
s.load(Config.USERNAME, Config.PASSWORD);
s.save();
s.loadFS();

var paths = s.getPaths();
print("PATHS = " + JSON.stringify(paths, false, '\t'));

var root = s.getNode("/Root");
var up = root.getUploader();
up.upload("test-aes", "xxxx-aes");


/*
var node = s.getNode("/Root/test-aes.c");
var dl = node.getDownloader();

print("Downloading: " + node.name + " (size " + GLib.format_size_for_display(node.size) + ")");
dl.download("dl1.dat", 0, 2);
dl.download("dl2.dat", 5, 15);
dl.download("dl3.dat", 55, 401);
*/

print("Done!");
