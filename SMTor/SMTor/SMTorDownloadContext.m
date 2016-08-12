/*
 *  SMTorDownloadContext.m
 *
 *  Copyright 2016 Avérous Julien-Pierre
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


#import <CommonCrypto/CommonCrypto.h>

#import "SMTorDownloadContext.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorDownloadContext
*/
#pragma mark - SMTorDownloadContext

@implementation SMTorDownloadContext
{
	FILE			*_file;
	NSUInteger		_bytesDownloaded;
	CC_SHA256_CTX	_sha256;
}

- (nullable instancetype)initWithPath:(NSString *)path
{
	self = [super init];
	
	if (self)
	{
		NSAssert(path, @"path is nil");
		
		// Create directory.
		[[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
		
		// Create file.
		_file = fopen([path fileSystemRepresentation], "w");
		
		if (!_file)
			return nil;
		
		// Init sha256.
		CC_SHA256_Init(&_sha256);
	}
	
	return self;
}

- (void)dealloc
{
	[self close];
}

- (void)handleData:(NSData *)data
{
	if ([data length] == 0)
		return;
	
	// Write data.
	if (_file)
	{
		if (fwrite([data bytes], [data length], 1, _file) == 1)
		{
			CC_SHA256_Update(&_sha256, [data bytes], (CC_LONG)[data length]);
		}
	}
	
	// Update count.
	_bytesDownloaded += [data length];
	
	// Call handler.
	if (_updateHandler)
		_updateHandler(self, _bytesDownloaded, NO, nil);
}

- (void)handleComplete:(NSError *)error
{
	[self close];
	
	if (_updateHandler)
		_updateHandler(self, _bytesDownloaded, YES, error);
}

- (NSData *)sha256
{
	NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA256_DIGEST_LENGTH];
	
	CC_SHA256_Final([result mutableBytes], &_sha256);
	
	return result;
}

- (void)close
{
	if (!_file)
		return;
	
	fclose(_file);
	_file = NULL;
}

@end


NS_ASSUME_NONNULL_END
