/*
 *  SMTorConstants.h
 *
 *  Copyright 2019 Avérous Julien-Pierre
 *
 *  This file is part of SMTor.
 *
 *  SMTor is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SMTor is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SMTor.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#pragma once


// Control.
#define SMTorControlHostFile	@"tor_ctrl"


// Local binary directory.
// > Root.
#define SMTorFileBinSignature	@"Signature"
#define SMTorFileBinBinaries	@"Binaries"
#define SMTorFileBinInfo		@"Info.plist"

// > Binaries > tor.
#define SMTorFileBinTor			@"tor"

// Info.plist > keys.
#define SMTorKeyInfoFiles		@"files"
#define SMTorKeyInfoTorVersion	@"tor_version"
#define SMTorKeyInfoHash		@"sha256"


// Remote archive.
// > URLs.
#define SMTorBaseUpdateURL			@"https://www.sourcemac.com/tor/%@"
#define SMTorInfoUpdateURL			@"https://www.sourcemac.com/tor/info.plist"
#define SMTorInfoSignatureUpdateURL	@"https://www.sourcemac.com/tor/info.plist.sig"

// > info.plist > keys.
#define SMTorKeyArchiveSize		@"size"
#define SMTorKeyArchiveName		@"name"
#define SMTorKeyArchiveVersion	@"version"
#define SMTorKeyArchiveHash		@"sha256"
