//
//  SMTorDownloadContext.m
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#import <CommonCrypto/CommonCrypto.h>

#import "SMTorDownloadContext.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorDownloadContext
*/
#pragma mark - SMTorDownloadContext

@implementation SMTorDownloadContext
{
	FILE		*_file;
	NSUInteger	_bytesDownloaded;
	CC_SHA1_CTX	_sha1;
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
		
		// Init sha1.
		CC_SHA1_Init(&_sha1);
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
			CC_SHA1_Update(&_sha1, [data bytes], (CC_LONG)[data length]);
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

- (NSData *)sha1
{
	NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
	
	CC_SHA1_Final([result mutableBytes], &_sha1);
	
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
