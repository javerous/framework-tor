/*
 *  SMTorOperations.m
 *
 *  Copyright 2018 Avérous Julien-Pierre
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
#import <SMFoundation/SMFoundation.h>

#import "SMTorOperations.h"

#import "SMTorConfiguration.h"

#import "SMPublicKey.h"
#import "SMTorConstants.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Prototypes
*/
#pragma mark - Prototypes

static NSData * _Nullable file_sha256(NSURL *fileURL);



/*
** SMTorOperations
*/
#pragma mark - SMTorOperations

@implementation SMTorOperations


+ (void)operationStageArchiveFile:(NSURL *)fileURL toTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler
{
	// Check parameters.
	if (!handler)
		handler = ^(SMInfo *error) { };
	
	if (!fileURL)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorInternal]);
		return;
	}
	
	NSFileManager *fileManager = [NSFileManager defaultManager];
	
	// Get target directory.
	if ([torBinPath hasSuffix:@"/"])
		torBinPath = [torBinPath substringToIndex:(torBinPath.length - 1)];
	
	if (!torBinPath)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationIO]);
		return;
	}
	
	// Create target directory.
	if ([fileManager createDirectoryAtPath:torBinPath withIntermediateDirectories:YES attributes:nil error:nil] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationConfiguration]);
		return;
	}
	
	// Copy tarball.
	NSString *filePath = fileURL.path;
	NSString *newFilePath = [torBinPath stringByAppendingPathComponent:@"_temp.tgz"];
	
	[fileManager removeItemAtPath:newFilePath error:nil];
	
	if (!filePath || [fileManager copyItemAtPath:filePath toPath:newFilePath error:nil] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationIO]);
		return;
	}
	
	// Configure sandbox.
	NSMutableString *profile = [[NSMutableString alloc] init];
	
	[profile appendFormat:@"(version 1)"];
	[profile appendFormat:@"(deny default (with no-log))"];						// Deny all by default.
	[profile appendFormat:@"(allow process-fork process-exec)"];				// Allow fork-exec
	[profile appendFormat:@"(allow file-read* (subpath \"/usr/lib\"))"];		// Allow to read libs.
	[profile appendFormat:@"(allow file-read* (literal \"/usr/bin/tar\"))"];	// Allow to read tar (execute).
	[profile appendFormat:@"(allow file-read* (literal \"%@\"))", [newFilePath stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]]; // Allow to read the archive.
	[profile appendFormat:@"(allow file* (subpath \"%@\"))", [torBinPath stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]];	// Allow to write result.
	
#if DEBUG
	[profile appendFormat:@"(allow file-read* (subpath \"/System/Library\"))"];	// Allow to read system things.
	[profile appendFormat:@"(allow file-read* (subpath \"/Applications\"))"];	// Allow to read Applications.
#endif
	
	// Create & launch task.
	NSTask *task = [[NSTask alloc] init];
	
	task.launchPath = @"/usr/bin/sandbox-exec";
	task.currentDirectoryPath = torBinPath;
	
	task.arguments = @[ @"-p", profile, @"/usr/bin/tar", @"-x", @"-z", @"-f", newFilePath.lastPathComponent, @"--strip-components", @"1" ];
	
	[task setStandardError:nil];
	[task setStandardOutput:nil];
	
	task.terminationHandler = ^(NSTask *aTask) {
		
		if (aTask.terminationStatus != 0)
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationExtract context:@(aTask.terminationStatus)]);
		else
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationDone]);
		
		[fileManager removeItemAtPath:newFilePath error:nil];
	};
	
	@try {
		[task launch];
	}
	@catch (NSException *exception) {
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationExtract context:@(-1)]);
		[fileManager removeItemAtPath:newFilePath error:nil];
	}
}

+ (void)operationCheckSignatureWithTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler
{
	// Check parameters.
	if (!handler)
		handler = ^(SMInfo *info) { };
	
	// Get tor path.
	if (!torBinPath)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationConfiguration]);
		return;
	}
	
	// Build paths.
	NSString *signaturePath = [torBinPath stringByAppendingPathComponent:SMTorFileBinSignature];
	NSString *binariesPath = [torBinPath stringByAppendingPathComponent:SMTorFileBinBinaries];
	NSString *infoPath = [torBinPath stringByAppendingPathComponent:SMTorFileBinInfo];
	
	// Read signature.
	NSData *data = [NSData dataWithContentsOfFile:signaturePath];
	
	if (data.length == 0)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationIO]);
		return;
	}
	
	// Check signature.
	NSData *publicKey = [[NSData alloc] initWithBytesNoCopy:(void *)kPublicKey length:sizeof(kPublicKey) freeWhenDone:NO];
	
	if ([SMFileSignature validateSignature:data fileURL:[NSURL fileURLWithPath:infoPath] publicKey:publicKey] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationSignature context:infoPath]);
		return;
	}
	
	// Read info.plist.
	NSData			*infoData = [NSData dataWithContentsOfFile:infoPath];
	NSDictionary	*info = [NSPropertyListSerialization propertyListWithData:infoData options:NSPropertyListImmutable format:nil error:nil];
	
	if (!info)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationIO]);
		return;
	}
	
	// Give info.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationInfo context:info]);
	
	// Check files hash.
	NSDictionary *files = info[SMTorKeyInfoFiles];
	
	for (NSString *file in files)
	{
		NSString		*filePath = [binariesPath stringByAppendingPathComponent:file];
		NSDictionary	*fileInfo = files[file];
		NSData			*infoHash = fileInfo[SMTorKeyInfoHash];
		NSData			*diskHash = file_sha256([NSURL fileURLWithPath:filePath]);
		
		if (!diskHash || [infoHash isEqualToData:diskHash] == NO)
		{
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationSignature context:filePath]);
			return;
		}
	}
	
	// Finish.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationDone]);
}

@end



/*
** C Tools
*/
#pragma mark - C Tools

static NSData * _Nullable file_sha256(NSURL *fileURL)
{
	assert(fileURL);
	
	// Open file.
	NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingFromURL:fileURL error:nil];
	
	if (!fileHandle)
		return nil;
	
	// Create SHA256 digester.
	CC_SHA256_CTX context;
	
	CC_SHA256_Init(&context);
	
	// Read chunk.
	while (1)
	{
		NSData *chunk;
		
		@try {
			chunk = [fileHandle readDataOfLength:4096];
		} @catch (NSException *exception) {
			return nil;
		}
		
		if (chunk.length == 0)
			break;
		
		CC_SHA256_Update(&context, chunk.bytes, (CC_LONG)chunk.length);
	}
	
	// Finalize.
	uint8_t digest[CC_SHA256_DIGEST_LENGTH];
	
	CC_SHA256_Final(digest, &context);
	
	// Return.
	return [NSData dataWithBytes:digest length:sizeof(digest)];
}

NS_ASSUME_NONNULL_END
