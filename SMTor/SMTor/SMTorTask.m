//
//  SMTorTask.m
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#if defined(DEBUG) && DEBUG
# include <libproc.h>
#endif

#import "SMTorTask.h"

#import "SMTorControl.h"
#import "SMTorOperations.h"
#import "SMTorDownloadContext.h"

#import "SMTorConfiguration.h"

#import "SMTorConstants.h"


NS_ASSUME_NONNULL_BEGIN


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
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorInfoStartDomain code:SMTorErrorStartSignature info:info];
					ctrl(SMOperationsControlFinish);
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
			
			[SMTorOperations operationLaunchTorWithConfiguration:configuration logHandler:logHandler completionHandler:^(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable aCtrlKeyHexa) {
				
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
			
			// Continue on next operation.
			opCtrl(SMOperationsControlContinue);
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

@end


NS_ASSUME_NONNULL_END

