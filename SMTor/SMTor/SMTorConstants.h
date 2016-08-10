//
//  SMTorConstants.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#ifndef SMTorConstants_h
#define SMTorConstants_h

// Control.
#define SMTorControlHostFile	@"tor_ctrl"

// Binary files.
#define SMTorFileBinSignature	@"Signature"
#define SMTorFileBinBinaries	@"Binaries"
#define SMTorFileBinInfo		@"Info.plist"

// Binary tor.
#define SMTorFileBinTor			@"tor"

// Binary info.
#define SMTorKeyInfoFiles		@"files"
#define SMTorKeyInfoTorVersion	@"tor_version"
#define SMTorKeyInfoHash		@"hash"

// URLs
#define SMTorBaseUpdateURL			@"http://www.sourcemac.com/tor/%@"
#define SMTorInfoUpdateURL			@"http://www.sourcemac.com/tor/info.plist"
#define SMTorInfoSignatureUpdateURL	@"http://www.sourcemac.com/tor/info.plist.sig"

// Remote archive.
#define SMTorKeyArchiveSize		@"size"
#define SMTorKeyArchiveName		@"name"
#define SMTorKeyArchiveVersion	@"version"
#define SMTorKeyArchiveHash		@"hash"

#endif /* SMTorConstants_h */
