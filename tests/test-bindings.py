#
# megatools - Mega.co.nz client library and tools
# Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from gi.repository import Mega

#print(Mega.base64urldecode(Mega.base64urlencode("test")))

pkey = Mega.AesKey.new_generated()
mkey = Mega.AesKey.new_generated()

print(pkey.get_ubase64())

print(Mega.format_hex(pkey.get_enc_binary(mkey), Mega.HexFormat.PACKED))
print(Mega.format_hex(mkey.encrypt_raw(pkey.get_binary()), Mega.HexFormat.PACKED))

http = Mega.HttpClient.new()
x = http.post_simple('http://localhost', b'qwe')
print(x.str)
