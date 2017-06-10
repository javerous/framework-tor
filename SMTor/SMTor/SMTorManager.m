/*
 *  SMTorManager.m
 *
 *  Copyright 2017 Avérous Julien-Pierre
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

#import <SMFoundation/SMFoundation.h>

#include <signal.h>

#import "SMTorManager.h"

#import "SMTorConfiguration.h"

#import "SMPublicKey.h"
#import "SMTorConstants.h"

#import "SMTorTask.h"
#import "SMTorControl.h"
#import "SMTorDownloadContext.h"
#import "SMTorOperations.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Prototypes
*/
#pragma mark - Prototypes

// Version.
static BOOL	version_greater(NSString * _Nullable baseVersion, NSString * _Nullable newVersion);



/*
** SMTorManager
*/
#pragma mark - SMTorManager

@implementation SMTorManager
{
	// Queues.
	dispatch_queue_t	_localQueue;
	dispatch_queue_t	_eventQueue;
	
	SMTorConfiguration	*_configuration;
	
	dispatch_source_t	_termSource;
	
	SMOperationsQueue	*_opQueue;
	
	// Task.
	SMTorTask			*_torTask;
	
	// Termination.
	id <NSObject>		_terminationObserver;
	
	// URL Session.
	NSURLSession		*_urlSession;
}



/*
** SMTorManager - Instance
*/
#pragma mark - SMTorManager - Instance

+ (void)initialize
{
	[self registerInfoDescriptors];
}

- (nullable instancetype)initWithConfiguration:(SMTorConfiguration *)configuration
{
	NSAssert(configuration, @"configuration is nil");

	self = [super init];
	
    if (self)
	{
		// Handle configuration.
		_configuration = [configuration copy];
		
		if (_configuration.isValid == NO)
			return nil;
		
		// Create queues.
        _localQueue = dispatch_queue_create("com.smtor.tormanager.local", DISPATCH_QUEUE_SERIAL);
		_eventQueue = dispatch_queue_create("com.smtor.tormanager.event", DISPATCH_QUEUE_SERIAL);
		
		// Operations queue.
		_opQueue = [[SMOperationsQueue alloc] initStarted];
		
		// Handle application standard termination.
		_terminationObserver = [[NSNotificationCenter defaultCenter] addObserverForName:NSApplicationWillTerminateNotification object:nil queue:nil usingBlock:^(NSNotification * _Nonnull note) {
			
			dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

			[self stopWithCompletionHandler:^{
				dispatch_semaphore_signal(semaphore);
			}];
			
			dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
		}];
		
		// SIGTERM handle.
		signal(SIGTERM, SIG_IGN);

		_termSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, _localQueue);
		
		dispatch_source_set_event_handler(_termSource, ^{
			
			[self stopWithCompletionHandler:^{
				exit(0);
			}];
		});
		
		dispatch_resume(_termSource);
	}
    
    return self;
}

- (void)dealloc
{
	// Stop notification.
	[[NSNotificationCenter defaultCenter] removeObserver:_terminationObserver];
}



/*
** SMTorManager - Life
*/
#pragma mark - SMTorManager - Life

- (void)startWithInfoHandler:(nullable void (^)(SMInfo *info))handler
{
	if (!handler)
		handler = ^(SMInfo *error) { };

	[_opQueue scheduleBlock:^(SMOperationsControl opCtrl) {
		
		SMOperationsQueue *queue = [[SMOperationsQueue alloc] init];
		
		// -- Stop current instance --
		[queue scheduleBlock:^(SMOperationsControl ctrl) {
			[self stopWithCompletionHandler:^{
				ctrl(SMOperationsControlContinue);
			}];
		}];
		
		// -- Start new instance --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {

			_torTask = [[SMTorTask alloc] init];
			
			[_torTask startWithConfiguration:_configuration logHandler:self.logHandler completionHandler:^(SMInfo *info) {
				
				switch (info.kind)
				{
					case SMInfoInfo:
					{
						switch ((SMTorEventStart)(info.code))
						{
							case SMTorEventStartURLSession:
							{
								dispatch_async(_localQueue, ^{
									_urlSession = info.context;
								});
								break;
							}
								
							case SMTorEventStartDone:
							{
								ctrl(SMOperationsControlContinue);
								break;
							}
							
							default:
								break;
						}
						
						break;
					}
						
					case SMInfoWarning:
					{
						if (info.code == SMTorWarningStartCanceled)
						{
							dispatch_async(_localQueue, ^{
								{
									_torTask = nil;
									_urlSession = nil;
								}
							});
							
							ctrl(SMOperationsControlContinue);
						}
						
						break;
					}
						
					case SMInfoError:
					{
						dispatch_async(_localQueue, ^{
							_torTask = nil;
							_urlSession = nil;
						});
						
						ctrl(SMOperationsControlContinue);
						
						break;
					}
				}
				
				handler(info);
			}];
		}];
		
		// -- Finish --
		queue.finishHandler = ^(BOOL canceled) {
			opCtrl(SMOperationsControlContinue);
		};
		
		// -- Start --
		[queue start];
	}];
}

- (void)stopWithCompletionHandler:(nullable dispatch_block_t)handler
{
	dispatch_async(_localQueue, ^{
		
		SMTorTask *torTask = _torTask;
		
		if (torTask)
		{
			_torTask = nil;
			_urlSession = nil;

			[torTask stopWithCompletionHandler:handler];
		}
		else
		{
			if (handler)
				dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), (dispatch_block_t)handler);
		}
	});
}



/*
** SMTorManager - Update
*/
#pragma mark - SMTorManager - Update

- (dispatch_block_t)checkForUpdateWithInfoHandler:(void (^)(SMInfo *info))handler
{
	NSAssert(handler, @"handler is nil");
	
	SMOperationsQueue *queue = [[SMOperationsQueue alloc] init];

	[_opQueue scheduleBlock:^(SMOperationsControl opCtrl) {
		
		// -- Check that we are running --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			if (!_torTask || !_urlSession)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoCheckUpdateDomain code:SMTorErrorCheckUpdateTorNotRunning]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Retrieve remote info --
		__block NSString *remoteVersion = nil;
		
		[queue scheduleCancelableOnQueue:_localQueue block:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {

			dispatch_block_t cancelHandler;
			
			cancelHandler = [self.class operationRetrieveRemoteInfoWithURLSession:_urlSession completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoCheckUpdateDomain code:SMTorErrorRetrieveRemoteInfo info:info]);
					ctrl(SMOperationsControlFinish);
				}
				if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationInfo)
					{
						NSDictionary *remoteInfo = info.context;
						
						remoteVersion = remoteInfo[SMTorKeyArchiveVersion];
						
						ctrl(SMOperationsControlContinue);
					}
				}
			}];
			
			addCancelBlock(cancelHandler);
		}];
		
		// -- Check local signature --
		__block NSString *localVersion = nil;
		
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			[SMTorOperations operationCheckSignatureWithTorBinariesPath:_configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoCheckUpdateDomain code:SMTorErrorCheckUpdateLocalSignature info:info]);
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationInfo)
					{
						localVersion = ((NSDictionary *)info.context)[SMTorKeyInfoTorVersion];
					}
					else if (info.code == SMTorEventOperationDone)
					{
						ctrl(SMOperationsControlContinue);
					}
				}
			}];
		}];
		
		// -- Compare versions --
		[queue scheduleBlock:^(SMOperationsControl ctrl) {
			
			if (version_greater(localVersion, remoteVersion))
			{
				NSDictionary *context = @{ @"old_version" : localVersion, @"new_version" : remoteVersion };
				
				handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoCheckUpdateDomain code:SMTorEventCheckUpdateAvailable context:context]);
			}
			else
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoCheckUpdateDomain code:SMTorErrorCheckUpdateNothingNew]);
			
			ctrl(SMOperationsControlFinish);
		}];
		
		// -- Finish --
		queue.finishHandler = ^(BOOL canceled) {
			opCtrl(SMOperationsControlContinue);
		};
		
		// Start.
		[queue start];
	}];
	
	// Return cancel block.
	return ^{
		SMDebugLog(@"<cancel checkForUpdateWithInfoHandler (global)>");
		[queue cancel];
	};
}

- (dispatch_block_t)updateWithInfoHandler:(void (^)(SMInfo *info))handler
{
	NSAssert(handler, @"handler is nil");

	SMOperationsQueue *queue = [[SMOperationsQueue alloc] init];
	
	[_opQueue scheduleBlock:^(SMOperationsControl opCtrl) {
	
		// -- Check that we are running --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			if (!_torTask || !_urlSession)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateTorNotRunning]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Retrieve remote info --
		__block NSString	*remoteName = nil;
		__block NSData		*remoteHash = nil;
		__block NSNumber	*remoteSize = nil;
		
		[queue scheduleCancelableOnQueue:_localQueue block:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
			
			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateArchiveInfoRetrieving]);
	
			// Retrieve remote informations.
			dispatch_block_t opCancel;

			opCancel = [self.class operationRetrieveRemoteInfoWithURLSession:_urlSession completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateArchiveInfo info:info]);
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationInfo)
					{
						NSDictionary *remoteInfo = info.context;
						
						remoteName = remoteInfo[SMTorKeyArchiveName];
						remoteHash = remoteInfo[SMTorKeyArchiveHash];
						remoteSize = remoteInfo[SMTorKeyArchiveSize];
						
						ctrl(SMOperationsControlContinue);
					}
				}
			}];
			
			// Add cancelation block.
			addCancelBlock(opCancel);
		}];
		
		// -- Retrieve remote archive --
		NSString *downloadPath =  [_configuration.dataPath stringByAppendingPathComponent:@"_update"];
		NSString *downloadArchivePath = [downloadPath stringByAppendingPathComponent:@"tor.tgz"];
		
		[queue scheduleCancelableOnQueue:_localQueue block:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {

			// Create url.
			NSString	*urlString = [NSString stringWithFormat:SMTorBaseUpdateURL, remoteName];
			NSURL		*url = [NSURL URLWithString:urlString];
			
			// Create task.
			NSURLSessionDataTask *task = [_urlSession dataTaskWithURL:url];
			
			// Get download path.
			if (!downloadPath)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateConfiguration]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Create context.
			SMTorDownloadContext *context = [[SMTorDownloadContext alloc] initWithPath:downloadArchivePath];
			
			if (!context)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateInternal]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			context.updateHandler = ^(SMTorDownloadContext *aContext, NSUInteger bytesDownloaded, BOOL complete, NSError *error) {
				
				// > Handle complete.
				if (complete || bytesDownloaded > remoteSize.unsignedIntegerValue)
				{
					if (complete)
					{
						if (error)
						{
							handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateArchiveDownload context:error]);
							ctrl(SMOperationsControlFinish);
							return;
						}
					}
					else
					{
						[task cancel];
						[aContext close];
					}
					
					// > Remove context.
					[_torTask removeDownloadContextForKey:@(task.taskIdentifier)];
					
					// > Check hash.
					if ([[aContext sha256] isEqualToData:remoteHash] == NO)
					{
						handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateArchiveDownload context:error]);
						ctrl(SMOperationsControlFinish);
						return;
					}
					
					// > Continue.
					ctrl(SMOperationsControlContinue);
				}
				else
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateArchiveDownloading context:@(bytesDownloaded)]);
			};
			
			// Handle context.
			[_torTask addDownloadContext:context forKey:@(task.taskIdentifier)];
			
			// Resume task.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateArchiveSize context:remoteSize]);
			
			[task resume];
			
			addCancelBlock(^{
				SMDebugLog(@"Cancel <retrieve remote archive>");
				[task cancel];
			});
		}];
		
		// -- Stop tor --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			[self stopWithCompletionHandler:^{
				ctrl(SMOperationsControlContinue);
			}];
		}];
		
		// -- Stage archive --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {

			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateArchiveStage]);
			
			// Stage file.
			[SMTorOperations operationStageArchiveFile:[NSURL fileURLWithPath:downloadArchivePath] toTorBinariesPath:_configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateArchiveStage]);
					ctrl(SMOperationsControlFinish);
					return;
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Check signature --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateSignatureCheck]);
			
			// Check signature.
			[SMTorOperations operationCheckSignatureWithTorBinariesPath:_configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorCheckUpdateLocalSignature info:info]);
					ctrl(SMOperationsControlFinish);
					return;
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Launch binary --
		[queue scheduleCancelableOnQueue:_localQueue block:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {

			SMTorTask *torTask = [[SMTorTask alloc] init];
			
			[torTask startWithConfiguration:_configuration logHandler:self.logHandler completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorEventStartURLSession)
					{
						dispatch_async(_localQueue, ^{
							_urlSession = info.context;
						});
					}
					else if (info.code == SMTorEventStartDone)
					{
						dispatch_async(_localQueue, ^{
							_torTask = torTask;
						});
						
						ctrl(SMOperationsControlContinue);
					}
				}
				else if (info.kind == SMInfoWarning)
				{
					if (info.code == SMTorWarningStartCanceled)
					{
						handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateRelaunch info:info]);
						ctrl(SMOperationsControlFinish);
					}
				}
				else if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorInfoUpdateDomain code:SMTorErrorUpdateRelaunch info:info]);
					ctrl(SMOperationsControlFinish);
				}
			}];
			
			addCancelBlock(^{ [torTask stopWithCompletionHandler:nil]; });
		}];
		
		// -- Done --
		[queue scheduleBlock:^(SMOperationsControl ctrl) {

			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorInfoUpdateDomain code:SMTorEventUpdateDone]);
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Finish --
		queue.finishHandler = ^(BOOL canceled){
			if (downloadPath)
				[[NSFileManager defaultManager] removeItemAtPath:downloadPath error:nil];
			
			opCtrl(SMOperationsControlContinue);
		};
		
		// Start.
		[queue start];
	}];
	
	// Return cancel block.
	return ^{
		SMDebugLog(@"<cancel updateWithEventHandler (global)>");
		[queue cancel];
	};
}



/*
** SMTorManager - Configuration
*/
#pragma mark - SMTorManager - Configuration

- (BOOL)loadConfiguration:(SMTorConfiguration *)config infoHandler:(nullable void (^)(SMInfo *info))handler
{
	NSAssert(config, @"configuration is nil");

	SMTorConfiguration *configuration = [config copy];
	
	if (configuration.isValid == NO)
		return NO;
	
	if ([_configuration differFromConfiguration:configuration] == NO)
		return YES;
	
	// Handle change.
	[_opQueue scheduleBlock:^(SMOperationsControl opCtrl) {
		
		SMOperationsQueue *queue = [[SMOperationsQueue alloc] init];
		
		// -- Stop Tor --
		__block BOOL needTorRelaunch = NO;
		
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			SMDebugLog(@" -> Stop tor %@.", _torTask);
			
			if (_torTask)
			{
				needTorRelaunch = YES;
				
				[_torTask stopWithCompletionHandler:^{
					ctrl(SMOperationsControlContinue);
				}];
			}
			else
				ctrl(SMOperationsControlContinue);
		}];
		
		// -- Move files --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			SMDebugLog(@" -> Move files.");
			
			if ([_configuration.binaryPath isEqualToString:configuration.binaryPath] == NO)
				[self _moveTorBinaryFilesToPath:configuration.binaryPath];

			if ([_configuration.dataPath isEqualToString:configuration.dataPath] == NO)
				[self _moveTorDataFilesToPath:configuration.dataPath];
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Relaunch tor --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			if (!needTorRelaunch)
			{
				ctrl(SMOperationsControlContinue);
				return;
			}
			
			SMDebugLog(@" -> Relaunch tor.");
			
			_configuration = configuration;
			
			SMTorTask *torTask = [[SMTorTask alloc] init];
			
			[torTask startWithConfiguration:_configuration logHandler:self.logHandler completionHandler:^(SMInfo *info) {
				
				switch (info.kind)
				{
					case SMInfoInfo:
					{
						if (info.code == SMTorEventStartURLSession)
						{
							dispatch_async(_localQueue, ^{
								_urlSession = info.context;
							});
						}
						else if (info.code == SMTorEventStartDone)
						{
							dispatch_async(_localQueue, ^{
								_torTask = torTask;
							});
							
							ctrl(SMOperationsControlContinue);
						}
						break;
					}
						
					case SMInfoWarning:
					{
						if (info.code == SMTorWarningStartCanceled)
							ctrl(SMOperationsControlFinish);
						break;
					}
						
					case SMInfoError:
					{
						ctrl(SMOperationsControlFinish);
						break;
					}
				}
				
				if (handler)
					handler(info);
			}];
		}];
		
		// -- Finish --
		queue.finishHandler = ^(BOOL canceled) {
			opCtrl(SMOperationsControlContinue);
		};
		
		// Start.
		[queue start];
	}];
	
	return YES;
}

- (SMTorConfiguration *)configuration
{
	__block SMTorConfiguration *configuration;
	
	dispatch_sync(_localQueue, ^{
		configuration = [_configuration copy];
	});
	
	return configuration;
}



/*
** SMTorManager - Path Change
*/
#pragma mark - SMTorManager - Path Change

- (void)_moveTorBinaryFilesToPath:(NSString *)newBinaryPath
{
	// > localQueue <
	
	SMDebugLog(@"~binPath - move files.");
	
	NSError *error = nil;
	
	// Compose paths.
	NSString *oldPathSignature = [_configuration.binaryPath stringByAppendingPathComponent:SMTorFileBinSignature];
	NSString *oldPathInfo = [_configuration.binaryPath stringByAppendingPathComponent:SMTorFileBinInfo];
	NSString *oldPathBinaries = [_configuration.binaryPath stringByAppendingPathComponent:SMTorFileBinBinaries];
	
	NSString *newPathSignature = [newBinaryPath stringByAppendingPathComponent:SMTorFileBinSignature];
	NSString *newPathInfo = [newBinaryPath stringByAppendingPathComponent:SMTorFileBinInfo];
	NSString *newPathBinaries = [newBinaryPath stringByAppendingPathComponent:SMTorFileBinBinaries];
	
	// Create target directory.
	if ([[NSFileManager defaultManager] createDirectoryAtPath:newBinaryPath withIntermediateDirectories:YES attributes:nil error:&error] == NO)
	{
		if (error.domain != NSCocoaErrorDomain || error.code != NSFileWriteFileExistsError)
		{
			NSLog(@"Error: Can't create target directory (%@)", error);
			return;
		}
	}
	
	// Move paths.
	if ([[NSFileManager defaultManager] moveItemAtPath:oldPathSignature toPath:newPathSignature error:&error] == NO)
	{
		NSLog(@"Error: Can't move signature file (%@)", error);
		return;
	}
	
	if ([[NSFileManager defaultManager] moveItemAtPath:oldPathInfo toPath:newPathInfo error:&error] == NO)
	{
		NSLog(@"Error: Can't move info file (%@)", error);
		return;
	}
	
	if ([[NSFileManager defaultManager] moveItemAtPath:oldPathBinaries toPath:newPathBinaries error:&error] == NO)
	{
		NSLog(@"Error: Can't move binaries directory (%@)", error);
		return;
	}
}

- (void)_moveTorDataFilesToPath:(NSString *)newDataPath
{
	// > localQueue <

	SMDebugLog(@"~dataPath - move files.");

	NSError *error = nil;
	
	// Create target directory.
	if ([[NSFileManager defaultManager] createDirectoryAtPath:newDataPath withIntermediateDirectories:YES attributes:nil error:&error] == NO)
	{
		if (error.domain != NSCocoaErrorDomain || error.code != NSFileWriteFileExistsError)
		{
			NSLog(@"Error: Can't create target directory (%@)", error);
			return;
		}
	}
}



/*
** SMTorManager - Helpers
*/
#pragma mark - SMTorManager - Helpers

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
			
			if ([SMDataSignature validateSignature:data data:remoteInfoData publicKey:publicKey] == NO)
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



/*
** SMTorManager - Infos
*/
#pragma mark - SMTorManager - Infos

+ (void)registerInfoDescriptors
{
	NSMutableDictionary *descriptors = [[NSMutableDictionary alloc] init];
	
	// == SMTorInfoStartDomain ==
	descriptors[SMTorInfoStartDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {
		
		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorEventStart)code)
				{
					case SMTorEventStartBootstrapping:
					{
						return @{
							SMInfoNameKey : @"SMTorEventStartBootstrapping",
							SMInfoDynTextKey : ^ NSString *(NSDictionary *context) {
								NSNumber	*progress = context[@"progress"];
								NSString	*summary = context[@"summary"];
									 
								return [NSString stringWithFormat:SMLocalizedString(@"tor_start_info_bootstrap", @""), progress.unsignedIntegerValue, summary];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
					
					case SMTorEventStartServiceID:
					{
						return @{
							SMInfoNameKey : @"SMTorEventStartServiceID",
							SMInfoDynTextKey : ^ NSString *(NSString *context) {
								return [NSString stringWithFormat:SMLocalizedString(@"tor_start_info_service_id", @""), context];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
						
					case SMTorEventStartServicePrivateKey:
					{
						return @{
							SMInfoNameKey : @"SMTorEventStartServicePrivateKey",
							SMInfoTextKey : @"tor_start_info_service_private_key",
							SMInfoLocalizableKey : @YES,
							};
					}
						
					case SMTorEventStartURLSession:
					{
						return @{
							SMInfoNameKey : @"SMTorEventStartURLSession",
							SMInfoTextKey : @"tor_start_info_url_session",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventStartDone:
					{
						return @{
							SMInfoNameKey : @"SMTorEventStartDone",
							SMInfoTextKey : @"tor_start_info_done",
							SMInfoLocalizableKey : @YES,
						  };
					}
				}
				break;
			}
				
			case SMInfoWarning:
			{
				switch ((SMTorWarningStart)code)
				{
					case SMTorWarningStartCanceled:
					{
						return @{
							SMInfoNameKey : @"SMTorWarningStartCanceled",
							SMInfoTextKey : @"tor_start_warning_canceled",
							SMInfoLocalizableKey : @YES,
						  };
					}
						
					case SMTorWarningStartCorruptedRetry:
					{
						return @{
							SMInfoNameKey : @"SMTorWarningStartCorruptedRetry",
							SMInfoTextKey : @"tor_start_warning_corrupted_retry",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
			
			case SMInfoError:
			{
				switch ((SMTorErrorStart)code)
				{
					case SMTorErrorStartAlreadyRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartAlreadyRunning",
							SMInfoTextKey : @"tor_start_err_already_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartConfiguration",
							SMInfoTextKey : @"tor_start_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartUnarchive:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartUnarchive",
							SMInfoTextKey : @"tor_start_err_unarchive",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartSignature",
							SMInfoTextKey : @"tor_start_err_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartLaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartLaunch",
							SMInfoTextKey : @"tor_start_err_launch",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartControlFile:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartControlFile",
							SMInfoTextKey : @"tor_start_err_control_file",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartControlConnect:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartControlConnect",
							SMInfoTextKey : @"tor_start_err_control_connect",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartControlAuthenticate:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartControlAuthenticate",
							SMInfoTextKey : @"tor_start_err_control_authenticate",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartControlHiddenService:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartControlHiddenService",
							SMInfoTextKey : @"tor_start_err_control_hiddenservice",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorStartControlMonitor:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorStartControlMonitor",
							SMInfoTextKey : @"tor_start_err_control_monitor",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
		}
		return nil;
	};
	
	// == SMTorInfoCheckUpdateDomain ==
	descriptors[SMTorInfoCheckUpdateDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorEventCheckUpdate)code)
				{
					case SMTorEventCheckUpdateAvailable:
					{
						return @{
							SMInfoNameKey : @"SMTorEventCheckUpdateAvailable",
							SMInfoDynTextKey : ^ NSString *(NSDictionary *context) {
								return [NSString stringWithFormat:SMLocalizedString(@"tor_checkupdate_info_version_available", @""), context[@"new_version"]];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
				}
				break;
			}
				
			case SMInfoWarning:
			{
				break;
			}
				
			case SMInfoError:
			{
				switch ((SMTorErrorCheckUpdate)code)
				{
					case SMTorErrorCheckUpdateTorNotRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorCheckUpdateTorNotRunning",
							SMInfoTextKey : @"tor_checkupdate_error_not_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorRetrieveRemoteInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorRetrieveRemoteInfo",
							SMInfoTextKey : @"tor_checkupdate_error_check_remote_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorCheckUpdateLocalSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorCheckUpdateLocalSignature",
							SMInfoTextKey : @"tor_checkupdate_error_validate_local_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorCheckUpdateNothingNew:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorCheckUpdateNothingNew",
							SMInfoTextKey : @"tor_checkupdate_error_nothing_new",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
		}
		
		return nil;
	};
	
	// == SMTorInfoUpdateDomain ==
	descriptors[SMTorInfoUpdateDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorEventUpdate)code)
				{
					case SMTorEventUpdateArchiveInfoRetrieving:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateArchiveInfoRetrieving",
							SMInfoTextKey : @"tor_update_info_retrieve_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventUpdateArchiveSize:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateArchiveSize",
							SMInfoDynTextKey : ^ NSString *(NSNumber *context) {
								return [NSString stringWithFormat:SMLocalizedString(@"tor_update_info_archive_size", @""), context.unsignedLongLongValue];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
						
					case SMTorEventUpdateArchiveDownloading:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateArchiveDownloading",
							SMInfoTextKey : @"tor_update_info_downloading",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventUpdateArchiveStage:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateArchiveStage",
							SMInfoTextKey : @"tor_update_info_stage",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventUpdateSignatureCheck:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateSignatureCheck",
							SMInfoTextKey : @"tor_update_info_signature_check",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventUpdateRelaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateRelaunch",
							SMInfoTextKey : @"tor_update_info_relaunch",
							SMInfoLocalizableKey : @YES,
							};
					}
						
					case SMTorEventUpdateDone:
					{
						return @{
							SMInfoNameKey : @"SMTorEventUpdateDone",
							SMInfoTextKey : @"tor_update_info_done",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
				
			case SMInfoWarning:
			{
				break;
			}
				
			case SMInfoError:
			{
				switch ((SMTorErrorUpdate)code)
				{
					case SMTorErrorUpdateTorNotRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateTorNotRunning",
							SMInfoTextKey : @"tor_update_err_not_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateConfiguration",
							SMInfoTextKey : @"tor_update_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateInternal:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateInternal",
							SMInfoTextKey : @"tor_update_err_internal",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateArchiveInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateArchiveInfo",
							SMInfoTextKey : @"tor_update_err_archive_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateArchiveDownload:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateArchiveDownload",
							SMInfoTextKey : @"tor_update_err_archive_download",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateArchiveStage:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateArchiveStage",
							SMInfoTextKey : @"tor_update_err_archive_stage",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorUpdateRelaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorUpdateRelaunch",
							SMInfoTextKey : @"tor_update_err_relaunch",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
		}
		
		return nil;
	};
	
	// == SMTorInfoOperationDomain ==
	descriptors[SMTorInfoOperationDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorEventOperation)code)
				{
					case SMTorEventOperationInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorEventOperationInfo",
							SMInfoTextKey : @"tor_operation_info_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorEventOperationDone:
					{
						return @{
							SMInfoNameKey : @"SMTorEventOperationDone",
							SMInfoTextKey : @"tor_operation_info_done",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
				
			case SMInfoWarning:
			{
				break;
			}
				
			case SMInfoError:
			{
				switch ((SMTorErrorOperation)code)
				{
					case SMTorErrorOperationConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationConfiguration",
							SMInfoTextKey : @"tor_operation_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorOperationIO:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationIO",
							SMInfoTextKey : @"tor_operation_err_io",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorOperationNetwork:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationNetwork",
							SMInfoTextKey : @"tor_operation_err_network",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorOperationExtract:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationExtract",
							SMInfoTextKey : @"tor_operation_err_extract",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorOperationSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationSignature",
							SMInfoTextKey : @"tor_operation_err_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorOperationTor:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorOperationTor",
							SMInfoTextKey : @"tor_operation_err_tor",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorErrorInternal:
					{
						return @{
							SMInfoNameKey : @"SMTorErrorInternal",
							SMInfoTextKey : @"tor_operation_err_internal",
							SMInfoLocalizableKey : @YES,
						};
					}
				}
				break;
			}
		}
		
		return nil;
	};
	
	[SMInfo registerDomainsDescriptors:descriptors localizer:^NSString * _Nonnull(NSString * _Nonnull token) {
		return SMLocalizedString(token, @"");
	}];
}

@end



/*
** C Tools
*/
#pragma mark - C Tools

#pragma mark Version

static BOOL version_greater(NSString * _Nullable baseVersion, NSString * _Nullable newVersion)
{
	if (!newVersion)
		return NO;
	
	if (!baseVersion)
		return YES;
	
	NSArray		*baseParts = [baseVersion componentsSeparatedByString:@"."];
	NSArray		*newParts = [newVersion componentsSeparatedByString:@"."];
	NSUInteger	count = MAX([baseParts count], [newParts count]);
	
	for (NSUInteger i = 0; i < count; i++)
	{
		NSUInteger baseValue = 0;
		NSUInteger newValue = 0;
		
		if (i < baseParts.count)
			baseValue = (NSUInteger)[baseParts[i] intValue];
		
		if (i < newParts.count)
			newValue = (NSUInteger)[newParts[i] intValue];
		
		if (newValue > baseValue)
			return YES;
		else if (newValue < baseValue)
			return NO;
	}
	
	return NO;
}


NS_ASSUME_NONNULL_END
