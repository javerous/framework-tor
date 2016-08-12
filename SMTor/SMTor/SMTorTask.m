/*
 *  SMTorTask.m
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


#if defined(DEBUG) && DEBUG
# include <libproc.h>
#endif

#import <CommonCrypto/CommonCrypto.h>

#import "SMTorTask.h"

#import "SMTorControl.h"
#import "SMTorOperations.h"
#import "SMTorDownloadContext.h"

#import "SMTorConfiguration.h"

#import "SMTorConstants.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Prototypes
*/
#pragma mark - Prototypes

// Digest.
static NSString *s2k_from_data(NSData *data, uint8_t iterations);

// Hexa.
static NSString *hexa_from_bytes(const uint8_t *bytes, size_t len);
static NSString *hexa_from_data(NSData *data);



/*
** SMTorTask
*/
#pragma mark - SMTorTask

@implementation SMTorTask
{
	SMOperationsQueue	*_opQueue;
	dispatch_queue_t	_localQueue;
	
	BOOL _isRunning;
	
	NSTask *_task;
	
	NSURLSession		*_torURLSession;
	NSMutableDictionary	*_torDownloadContexts;
	
	__weak SMOperationsQueue *_currentStartOperation;
}


/*
** SMTorTask - Instance
*/
#pragma mark - SMTorTask - Instance

- (instancetype)init
{
	self = [super init];
	
	if (self)
	{
		// Queues.
		_localQueue = dispatch_queue_create("com.smtor.tor-task.local", DISPATCH_QUEUE_SERIAL);
		_opQueue = [[SMOperationsQueue alloc] initStarted];
		
		// Containers.
		_torDownloadContexts = [[NSMutableDictionary alloc] init];
	}
	
	return self;
}

- (void)dealloc
{
	SMDebugLog(@"SMTorTask dealloc");
}



/*
** SMTorTask - Life
*/
#pragma mark - SMTorTask - Life

- (void)startWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info))handler
{
	[self startWithConfiguration:configuration tryCounter:0 logHandler:logHandler completionHandler:handler];
}

- (void)startWithConfiguration:(SMTorConfiguration *)configuration tryCounter:(NSUInteger)tryCounter logHandler:(nullable void (^)(SMTorLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info))handler
{
	NSAssert(configuration, @"configuration is nil");
	NSAssert(handler, @"handler is nil");
	
#if defined(DEBUG) && DEBUG
	// To speed up debugging, if we are building in debug mode, do not launch a new tor instance if there is already one running.
	
	int count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	
	if (count > 0)
	{
		pid_t *pids = malloc((unsigned)count * sizeof(pid_t));
		
		count = proc_listpids(PROC_ALL_PIDS, 0, pids, count * (int)sizeof(pid_t));
		
		for (int i = 0; i < count; ++i)
		{
			char name[1024];
			
			if (proc_name(pids[i], name, sizeof(name)) > 0)
			{
				if (strcmp(name, "tor") == 0)
				{
					free(pids);
					
					// Create URL session.
					NSURLSessionConfiguration *sessionConfiguration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
					
					sessionConfiguration.connectionProxyDictionary =  @{ (NSString *)kCFStreamPropertySOCKSProxyHost : (configuration.socksHost ?: @"localhost"),
																		 (NSString *)kCFStreamPropertySOCKSProxyPort : @(configuration.socksPort) };
					
					_torURLSession = [NSURLSession sessionWithConfiguration:sessionConfiguration delegate:self delegateQueue:nil];
					
					// Give this session to caller.
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartURLSession context:_torURLSession]);
					
					// Say ready.
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartDone]);
					
					return;
				}
			}
		}
		
		free(pids);
	}
#endif
	
	[_opQueue scheduleBlock:^(SMOperationsControl opCtrl) {
		
		SMOperationsQueue	*operations = [[SMOperationsQueue alloc] init];
		__block SMInfo		*errorInfo = nil;
		
		// -- Stop if running --
		[operations scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			// Stop.
			if (_isRunning)
				[self _stop];
			
			_isRunning = YES;
			_currentStartOperation = operations;
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Stage archive --
		[operations scheduleBlock:^(SMOperationsControl ctrl) {
			
			// Check that the binary is already there.
			NSFileManager	*manager = [NSFileManager defaultManager];
			NSString		*path;
			
			path = [[configuration.binaryPath stringByAppendingPathComponent:SMTorFileBinBinaries] stringByAppendingPathComponent:SMTorFileBinTor];
			
			if ([manager fileExistsAtPath:path] == YES)
			{
				ctrl(SMOperationsControlContinue);
				return;
			}
			
			// Stage the archive.
			NSURL *archiveUrl = [[NSBundle bundleForClass:[self class]] URLForResource:@"tor" withExtension:@"tgz"];
			
			[SMTorOperations operationStageArchiveFile:archiveUrl toTorBinariesPath:configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartUnarchive info:info];
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Check signature --
		[operations scheduleBlock:^(SMOperationsControl ctrl) {
			
			[SMTorOperations operationCheckSignatureWithTorBinariesPath:configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					// Signature is not good. Retry by removing file (and make us re-staging).
					if (tryCounter == 0)
					{
						// Remove current staging.
						NSString *torBinPath = configuration.binaryPath;
						NSString *signaturePath = [torBinPath stringByAppendingPathComponent:SMTorFileBinSignature];
						NSString *binariesPath = [torBinPath stringByAppendingPathComponent:SMTorFileBinBinaries];
						NSString *infoPath = [torBinPath stringByAppendingPathComponent:SMTorFileBinInfo];
						
						[[NSFileManager defaultManager] removeItemAtPath:signaturePath error:nil];
						[[NSFileManager defaultManager] removeItemAtPath:binariesPath error:nil];
						[[NSFileManager defaultManager] removeItemAtPath:infoPath error:nil];

						// Try a new start.
						[self startWithConfiguration:configuration tryCounter:(tryCounter + 1) logHandler:logHandler completionHandler:handler];
						
						// Give a warning to user - Note: re-start wait on opQueue for this finish.
						errorInfo = [SMInfo infoOfKind:SMInfoWarning domain:SMTorInfoStartDomain code:SMTorWarningStartCorruptedRetry info:info];
						ctrl(SMOperationsControlFinish);
					}
					else
					{
						errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartSignature info:info];
						ctrl(SMOperationsControlFinish);
					}
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Launch binary --
		__block NSString *ctrlKeyHexa = nil;
		
		[operations scheduleBlock:^(SMOperationsControl ctrl) {
			
			[self.class operationLaunchTorWithConfiguration:configuration logHandler:logHandler completionHandler:^(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable aCtrlKeyHexa) {
				
				if (info.kind == SMInfoError)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartLaunch info:info];
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationDone)
					{
						ctrlKeyHexa = aCtrlKeyHexa;
						
						SMDebugLog(@"Tor Control Password: %@", ctrlKeyHexa);
						
						dispatch_async(_localQueue, ^{
							_task = task;
						});
						
						ctrl(SMOperationsControlContinue);
					}
				}
			}];
		}];
		
		// -- Wait control info --
		__block NSString *torCtrlAddress = nil;
		__block NSString *torCtrlPort = nil;
		
		[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
			
			// Get the hostname file path.
			NSString *ctrlInfoPath = [configuration.dataPath stringByAppendingPathComponent:SMTorControlHostFile];
			
			if (!ctrlInfoPath)
			{
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartConfiguration];
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Wait for file appearance.
			dispatch_source_t testTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _localQueue);
			
			dispatch_source_set_timer(testTimer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0);
			
			dispatch_source_set_event_handler(testTimer, ^{
				
				// Try to read file.
				NSString *ctrlInfo = [NSString stringWithContentsOfFile:ctrlInfoPath encoding:NSASCIIStringEncoding error:nil];
				
				if (!ctrlInfo)
					return;
				
				// Try to parse content.
				NSRegularExpression *regExp = [NSRegularExpression regularExpressionWithPattern:@"PORT[^=]*=[^0-9]*([0-9\\.]+):([0-9]+)" options:NSRegularExpressionCaseInsensitive error:nil];
				NSArray				*results = [regExp matchesInString:ctrlInfo options:0 range:NSMakeRange(0, ctrlInfo.length)];
				
				if (results == 0)
					return;
				
				// Remove info file once parsed.
				[[NSFileManager defaultManager] removeItemAtPath:ctrlInfoPath error:nil];
				
				// Extract infos.
				NSTextCheckingResult *result = results[0];
				
				if (result.numberOfRanges < 3)
					return;
				
				torCtrlAddress = [ctrlInfo substringWithRange:[result rangeAtIndex:1]];
				torCtrlPort = [ctrlInfo substringWithRange:[result rangeAtIndex:2]];
				
				// Stop ourself.
				dispatch_source_cancel(testTimer);
				
				// Continue.
				ctrl(SMOperationsControlContinue);
			});
			
			// Start timer
			dispatch_resume(testTimer);
			
			// Set cancelation.
			addCancelBlock(^{
				SMDebugLog(@"<cancel startWithBinariesPath (Wait control info)>");
				dispatch_source_cancel(testTimer);
			});
		}];
		
		// -- Create & authenticate control socket --
		__block SMTorControl *control;
		
		[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
			
			// Connect control.
			control = [[SMTorControl alloc] initWithIP:torCtrlAddress port:(uint16_t)[torCtrlPort intValue]];
			
			if (!control)
			{
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlConnect];
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Authenticate control.
			[control sendAuthenticationCommandWithKeyHexa:ctrlKeyHexa resultHandler:^(BOOL success) {
				
				if (!success)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlAuthenticate];
					ctrl(SMOperationsControlFinish);
					return;
				}
				
				ctrl(SMOperationsControlContinue);
			}];
			
			// Set cancelation.
			addCancelBlock(^{
				SMDebugLog(@"<cancel startWithBinariesPath (Create & authenticate control socket)>");
				[control stop];
				control = nil;
			});
		}];
		
		// -- Register hidden service --
		if (configuration.hiddenService)
		{
			[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
				
				NSString *servicePort = [NSString stringWithFormat:@"%u,%@:%u", configuration.hiddenServiceRemotePort, configuration.hiddenServiceLocalHost, configuration.hiddenServiceLocalPort];
				
				[control sendAddOnionCommandWithPrivateKey:configuration.hiddenServicePrivateKey port:servicePort resultHandler:^(BOOL success, NSString * _Nullable serviceID, NSString * _Nullable privateKey) {
					
					if (!success)
					{
						errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlHiddenService];
						ctrl(SMOperationsControlFinish);
						return;
					}
					
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartServiceID context:serviceID]);
					
					if (privateKey)
						handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartServicePrivateKey context:privateKey]);

					ctrl(SMOperationsControlContinue);
				}];
				
				
				// Set cancelation.
				addCancelBlock(^{
					SMDebugLog(@"<cancel startWithBinariesPath (Register hidden service)>");
					[control stop];
					control = nil;
				});
			}];
		}
		
		// -- Wait for bootstrap completion --
		[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
			
			// Check that we have a control.
			if (!control)
			{
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlMonitor];
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Snippet to handle bootstrap status.
			__block NSNumber *lastProgress = nil;
			
			void (^handleNoticeBootstrap)(NSString * _Nullable) = ^(NSString * _Nullable _content) {
				
				SMGuardReturn(_content, content);
				
				NSDictionary *bootstrap = [SMTorControl parseNoticeBootstrap:content];
				
				if (!bootstrap)
					return;
				
				NSNumber *progress = bootstrap[@"progress"];
				NSString *summary = bootstrap[@"summary"];
				NSString *tag = bootstrap[@"tag"];
				
				// Notify prrogress.
				if ([progress integerValue] > [lastProgress integerValue])
				{
					lastProgress = progress;
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartBootstrapping context:@{ @"progress" : progress, @"summary" : summary }]);
				}
				
				// Done.
				if ([tag isEqualToString:@"done"])
				{
					[control stop];
					control = nil;
					
					ctrl(SMOperationsControlContinue);
				}
			};
			
			// Handle server events.
			control.serverEvent = ^(NSString *type, NSString *content) {
				if ([type isEqualToString:@"STATUS_CLIENT"])
					handleNoticeBootstrap(content);
			};
			
			// Activate events.
			[control sendSetEventsCommandWithEvents:@"STATUS_CLIENT" resultHandler:^(BOOL success) {
				
				if (!success)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlMonitor];
					ctrl(SMOperationsControlFinish);
					return;
				}
			}];
			
			// Ask current status (because if we tor is already bootstrapped, we are not going to receive other bootstrap events).
			[control sendGetInfoCommandWithInfo:@"status/bootstrap-phase" resultHandler:^(BOOL success, NSString * _Nullable info) {
				
				if (!success)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartControlMonitor];
					ctrl(SMOperationsControlFinish);
					return;
				}
				
				handleNoticeBootstrap(info);
			}];
			
			// Set cancelation.
			addCancelBlock(^{
				SMDebugLog(@"<cancel startWithBinariesPath (Wait for bootstrap completion)>");
				[control stop];
				control = nil;
			});
		}];
		
		// -- NSURLSession --
		[operations scheduleBlock:^(SMOperationsControl ctrl) {
			
			// Create session configuration, and setup it to use tor.
			NSURLSessionConfiguration *sessionConfiguration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
			
			sessionConfiguration.connectionProxyDictionary =  @{ (NSString *)kCFStreamPropertySOCKSProxyHost : (configuration.socksHost ?: @"localhost"),
																 (NSString *)kCFStreamPropertySOCKSProxyPort : @(configuration.socksPort) };
			
			NSURLSession *urlSession = [NSURLSession sessionWithConfiguration:sessionConfiguration delegate:self delegateQueue:nil];
			
			dispatch_async(_localQueue, ^{
				_torURLSession = urlSession;
			});
			
			// Give this session to caller.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartURLSession context:urlSession]);
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		
		// -- Finish --
		operations.finishHandler = ^(BOOL canceled){
			
			// Handle error & cancelation.
			if (errorInfo || canceled)
			{
				if (canceled)
					handler([SMInfo infoOfKind:SMInfoWarning domain:SMTorInfoStartDomain code:SMTorWarningStartCanceled]);
				else
					handler(errorInfo);
				
				// Clean created things.
				dispatch_async(_localQueue, ^{
					[_task terminate];
					_task = nil;
					
					_torURLSession = nil;
				});
			}
			else
			{
				// Notify finish.
				handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoStartDomain code:SMTorEventStartDone]);
			}
			
			// Continue on next operation
			dispatch_async(_localQueue, ^{
				
				_currentStartOperation = nil;
				
				if (errorInfo || canceled)
					_isRunning = NO;
				
				opCtrl(SMOperationsControlContinue);
			});
		};
		
		// Start.
		[operations start];
	}];
}

- (void)stopWithCompletionHandler:(nullable dispatch_block_t)handler
{
	dispatch_async(_localQueue, ^{
		
		// Stop.
		[self _stop];
		
		// Wait for completion.
		if (handler)
		{
			[_opQueue scheduleBlock:^(SMOperationsControl ctrl) {
				handler();
				ctrl(SMOperationsControlContinue);
			}];
		}
	});
}

- (void)_stop
{
	// > localQueue <
	
	// Cancel any currently running operation.
	[_currentStartOperation cancel];
	_currentStartOperation = nil;
	
	// Terminate task.
	@try {
		[_task terminate];
		[_task waitUntilExit];
	} @catch (NSException *exception) {
		NSLog(@"Tor exception on terminate: %@", exception);
	}
	
	_task = nil;
	
	// Remove url session.
	[_torURLSession invalidateAndCancel];
	_torURLSession = nil;
	
	// Remove download contexts.
	[_torDownloadContexts removeAllObjects];
}



/*
** SMTorTask - NSURLSessionDelegate
*/
#pragma mark - SMTorTask - NSURLSessionDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data
{
	dispatch_async(_localQueue, ^{
		
		// Get context.
		SMTorDownloadContext *context = _torDownloadContexts[@(dataTask.taskIdentifier)];
		
		if (!context)
			return;
		
		// Handle data.
		[context handleData:data];
	});
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
	dispatch_async(_localQueue, ^{
		
		// Get context.
		SMTorDownloadContext *context = _torDownloadContexts[@(task.taskIdentifier)];
		
		if (!context)
			return;
		
		// Handle complete.
		[context handleComplete:error];
	});
}



/*
** SMTorTask - Download Context
*/
#pragma mark - SMTorTask - Download Context

- (void)addDownloadContext:(SMTorDownloadContext *)context forKey:(id <NSCopying>)key
{
	NSAssert(context, @"context is nil");
	NSAssert(key, @"key is nil");
	
	dispatch_async(_localQueue, ^{
		_torDownloadContexts[key] = context;
	});
}

- (void)removeDownloadContextForKey:(id)key
{
	NSAssert(key, @"key is nil");
	
	dispatch_async(_localQueue, ^{
		[_torDownloadContexts removeObjectForKey:key];
	});
}



/*
** SMTorTask - Helpers
*/
#pragma mark - SMTorTask - Helpers

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

