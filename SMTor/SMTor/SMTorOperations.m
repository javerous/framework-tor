//
//  SMTorOperations.m
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

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

// Digest.
static NSData *file_sha1(NSURL *fileURL);
static NSString *s2k_from_data(NSData *data, uint8_t iterations);

// Hexa.
static NSString *hexa_from_bytes(const uint8_t *bytes, size_t len);
static NSString *hexa_from_data(NSData *data);



/*
** SMTorOperations
*/
#pragma mark - SMTorOperations

@implementation SMTorOperations

+ (dispatch_block_t)operationRetrieveRemoteInfoWithURLSession:(NSURLSession *)urlSession completionHandler:(void (^)(SMInfo *info))handler
{
	NSAssert(handler, @"handler is nil");
	
	SMOperationsQueue *queue = [[SMOperationsQueue alloc] init];
	
	// -- Get remote info --
	__block NSData *remoteInfoData = nil;
	
	[queue scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
		
		// Create task.
		NSURL					*url = [NSURL URLWithString:SMTorInfoUpdateURL];
		NSURLSessionDataTask	*task;
		
		task = [urlSession dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
			
			// Check error.
			if (error)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationNetwork context:error]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Hold data.
			remoteInfoData = data;
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		// Resume task.
		[task resume];
		
		// Cancellation block.
		addCancelBlock(^{
			SMDebugLog(@"<cancel operationRetrieveRemoteInfoWithURLSession (Get remote info)>");
			[task cancel];
		});
	}];
	
	// -- Get signature, check it & parse plist --
	__block NSDictionary *remoteInfo = nil;
	
	[queue scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
		
		// Create task.
		NSURL					*url = [NSURL URLWithString:SMTorInfoSignatureUpdateURL];
		NSURLSessionDataTask	*task;
		
		task = [urlSession dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
			
			// Check error.
			if (data.length == 0 || error)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationNetwork context:error]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Check content.
			NSData *publicKey = [[NSData alloc] initWithBytesNoCopy:(void *)kPublicKey length:sizeof(kPublicKey) freeWhenDone:NO];
			
			if ([SMDataSignature validateSignature:data forData:remoteInfoData withPublicKey:publicKey] == NO)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationSignature context:error]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Parse content.
			NSError *pError = nil;
			
			remoteInfo = [NSPropertyListSerialization propertyListWithData:remoteInfoData options:NSPropertyListImmutable format:nil error:&pError];
			
			if (!remoteInfo)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorInternal context:pError]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Give result.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationInfo context:remoteInfo]);
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationDone context:remoteInfo]);
		}];
		
		// Resume task.
		[task resume];
		
		// Cancellation block.
		addCancelBlock(^{
			SMDebugLog(@"<cancel operationRetrieveRemoteInfoWithURLSession (Get signature, check it & parse plist)>");
			[task cancel];
		});
	}];
	
	// Queue start.
	[queue start];
	
	// Cancel block.
	return ^{
		SMDebugLog(@"<cancel operationRetrieveRemoteInfoWithURLSession (global)>");
		[queue cancel];
	};
}

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
		torBinPath = [torBinPath substringToIndex:([torBinPath length] - 1)];
	
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
	NSString *filePath = [fileURL path];
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
	
	[task setLaunchPath:@"/usr/bin/sandbox-exec"];
	[task setCurrentDirectoryPath:torBinPath];
	
	[task setArguments:@[ @"-p", profile, @"/usr/bin/tar", @"-x", @"-z", @"-f", [newFilePath lastPathComponent], @"--strip-components", @"1" ]];
	
	[task setStandardError:nil];
	[task setStandardOutput:nil];
	
	task.terminationHandler = ^(NSTask *aTask) {
		
		if ([aTask terminationStatus] != 0)
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationExtract context:@([aTask terminationStatus])]);
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
	
	if ([SMFileSignature validateSignature:data forContentsOfURL:[NSURL fileURLWithPath:infoPath] withPublicKey:publicKey] == NO)
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
		NSData			*diskHash = file_sha1([NSURL fileURLWithPath:filePath]);
		
		if (!diskHash || [infoHash isEqualToData:diskHash] == NO)
		{
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationSignature context:filePath]);
			return;
		}
	}
	
	// Finish.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationDone]);
}

+ (void)operationLaunchTorWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable ctrlKeyHexa))handler
{
	NSAssert(handler, @"handler is nil");
	
	// Check configuration.
	NSString *binaryPath = configuration.binaryPath;
	NSString *dataPath = configuration.dataPath;
	
	if (!binaryPath || !dataPath)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationConfiguration], nil, nil);
		return;
	}
	
	SMDebugLog(@"~~~~~ launch-tor");
	SMDebugLog(@"_torBinPath '%@'", binaryPath);
	SMDebugLog(@"_torDataPath '%@'", dataPath);
	SMDebugLog(@"-----");
	
	// Create directories.
	NSFileManager *mng = [NSFileManager defaultManager];
	
	[mng createDirectoryAtPath:dataPath withIntermediateDirectories:NO attributes:nil error:nil];
	[mng setAttributes:@{ NSFilePosixPermissions : @(0700) } ofItemAtPath:dataPath error:nil];
	
	// Clean previous file.
	[mng removeItemAtPath:[dataPath stringByAppendingPathComponent:SMTorControlHostFile] error:nil];
	
	// Create control password.
	NSMutableData	*ctrlPassword = [[NSMutableData alloc] initWithLength:32];
	NSString		*hashedPassword;
	NSString		*hexaPassword;
	
	arc4random_buf(ctrlPassword.mutableBytes, ctrlPassword.length);
	
	hashedPassword = s2k_from_data(ctrlPassword, 96);
	hexaPassword = hexa_from_data(ctrlPassword);
	
	// Log snippet.
	dispatch_queue_t logQueue = dispatch_queue_create("com.smtor.tor-task.output", DISPATCH_QUEUE_SERIAL);
	
	void (^handleLog)(NSFileHandle *, SMBuffer *buffer, SMTorLogKind) = ^(NSFileHandle *handle, SMBuffer *buffer, SMTorLogKind kind) {
		NSData *data;
		
		@try {
			data = [handle availableData];
		}
		@catch (NSException *exception) {
			handle.readabilityHandler = nil;
			return;
		}
		
		// Parse data.
		dispatch_async(logQueue, ^{
			
			NSData *line;
			
			[buffer appendBytes:[data bytes] ofSize:[data length] copy:YES];
			
			[buffer dataUpToCStr:"\n" includeSearch:NO];
			
			while ((line = [buffer dataUpToCStr:"\n" includeSearch:NO]))
			{
				NSString *string = [[NSString alloc] initWithData:line encoding:NSUTF8StringEncoding];
				
				logHandler(kind, string);
			}
		});
	};
	
	// Build tor task.
	NSTask *task = [[NSTask alloc] init];
	
	// > handle output.
	if (logHandler)
	{
		NSPipe		*errPipe = [[NSPipe alloc] init];
		NSPipe		*outPipe = [[NSPipe alloc] init];
		SMBuffer	*errBuffer = [[SMBuffer alloc] init];
		SMBuffer	*outBuffer =  [[SMBuffer alloc] init];
		
		NSFileHandle *errHandle = [errPipe fileHandleForReading];
		NSFileHandle *outHandle = [outPipe fileHandleForReading];
		
		errHandle.readabilityHandler = ^(NSFileHandle *handle) { handleLog(handle, errBuffer, SMTorLogError); };
		outHandle.readabilityHandler = ^(NSFileHandle *handle) { handleLog(handle, outBuffer, SMTorLogStandard); };
		
		[task setStandardError:errPipe];
		[task setStandardOutput:outPipe];
	}
	
	// > Set launch path.
	NSString *torExecPath = [[binaryPath stringByAppendingPathComponent:SMTorFileBinBinaries] stringByAppendingPathComponent:SMTorFileBinTor];
	
	[task setLaunchPath:torExecPath];
	
	// > Set arguments.
	NSMutableArray *args = [NSMutableArray array];
	
	[args addObject:@"--ClientOnly"];
	[args addObject:@"1"];
	
	
	[args addObject:@"--SocksPort"];
	[args addObject:[@(configuration.socksPort) stringValue]];
	
	[args addObject:@"--SocksListenAddress"];
	[args addObject:(configuration.socksHost ?: @"localhost")];
	
	[args addObject:@"--DataDirectory"];
	[args addObject:dataPath];
	
	[args addObject:@"--ControlPort"];
	[args addObject:@"auto"];
	
	[args addObject:@"--ControlPortWriteToFile"];
	[args addObject:[dataPath stringByAppendingPathComponent:SMTorControlHostFile]];
	
	[args addObject:@"--HashedControlPassword"];
	[args addObject:hashedPassword];
	
	[task setArguments:args];
	
	
	// Run tor task.
	@try {
		[task launch];
	} @catch (NSException *exception) {
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoOperationDomain code:SMTorErrorOperationTor context:@(-1)], nil, nil);
		return;
	}
	
	// Notify the launch.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoOperationDomain code:SMTorEventOperationDone], task, hexaPassword);
}

@end


NS_ASSUME_NONNULL_END


/*
** C Tools
*/
#pragma mark - C Tools

#pragma mark Digest

static NSData *file_sha1(NSURL *fileURL)
{
	assert(fileURL);
	
	// Declarations.
	NSData			*result = nil;
	CFReadStreamRef	readStream = NULL;
	SecTransformRef digestTransform = NULL;
	
	// Create read stream.
	readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, (__bridge CFURLRef)fileURL);
	
	if (!readStream)
		goto end;
	
	if (CFReadStreamOpen(readStream) != true)
		goto end;
	
	// Create digest transform.
	digestTransform = SecDigestTransformCreate(kSecDigestSHA1, 0, NULL);
	
	if (digestTransform == NULL)
		goto end;
	
	// Set digest input.
	SecTransformSetAttribute(digestTransform, kSecTransformInputAttributeName, readStream, NULL);
	
	// Execute.
	result = (__bridge_transfer NSData *)SecTransformExecute(digestTransform, NULL);
	
end:
	
	if (digestTransform)
		CFRelease(digestTransform);
	
	if (readStream)
	{
		CFReadStreamClose(readStream);
		CFRelease(readStream);
	}
	
	return result;
}

static NSString *s2k_from_data(NSData *data, uint8_t iterations)
{
	assert(data);
	
	size_t		dataLen = data.length;
	const void	*dataBytes = data.bytes;
	
	uint8_t	buffer[8 + 1 + CC_SHA1_DIGEST_LENGTH]; // 8 (salt) + 1 (iterations) + 20 (sha1)
	
	// Generate salt.
	arc4random_buf(buffer, 8);
	
	// Set number of iterations.
	buffer[8] = iterations;
	
	// Hash key.
	size_t	amount = ((uint32_t)16 + (iterations & 15)) << ((iterations >> 4) + 6);
	size_t	slen = 8 + dataLen;
	char	*sbytes = malloc(slen);
	
	memcpy(sbytes, buffer, 8);
	memcpy(sbytes + 8, dataBytes, dataLen);
	
	CC_SHA1_CTX ctx;
	
	CC_SHA1_Init(&ctx);
	
	while (amount)
	{
		if (amount >= slen)
		{
			CC_SHA1_Update(&ctx, sbytes, (CC_LONG)slen);
			amount -= slen;
		}
		else
		{
			CC_SHA1_Update(&ctx, sbytes, (CC_LONG)amount);
			amount = 0;
		}
	}
	
	CC_SHA1_Final(buffer + 9, &ctx);
	
	free(sbytes);
	
	// Generate hexadecimal.
	NSString *hexa = hexa_from_bytes(buffer, sizeof(buffer));
	
	return [@"16:" stringByAppendingString:hexa];
}


#pragma mark Hexa

static NSString *hexa_from_bytes(const uint8_t *bytes, size_t len)
{
	assert(bytes);
	assert(len > 0);
	
	static char hexTable[] = "0123456789abcdef";
	NSMutableString *result = [[NSMutableString alloc] init];
	
	for (size_t i = 0; i < len; i++)
	{
		uint8_t ch = bytes[i];
		
		[result appendFormat:@"%c%c", hexTable[(ch >> 4) & 0xf], hexTable[(ch & 0xf)]];
	}
	
	return result;
}

NSString *hexa_from_data(NSData *data)
{
	assert(data);
	
	return hexa_from_bytes(data.bytes, data.length);
}
