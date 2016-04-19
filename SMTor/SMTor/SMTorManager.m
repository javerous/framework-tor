/*
 *  SMTorManager.m
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

#import <SMFoundation/SMFoundation.h>
#import <CommonCrypto/CommonCrypto.h>

#include <signal.h>

#if defined(DEBUG) && DEBUG
# include <libproc.h>
#endif

#import "SMTorManager.h"

#import "SMTorConfiguration.h"

#import "SMPublicKey.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Defines
*/
#pragma mark - Defines

// Binary
#define SMTorManagerFileBinSignature	@"Signature"
#define SMTorManagerFileBinBinaries		@"Binaries"
#define SMTorManagerFileBinInfo			@"Info.plist"
#define SMTorManagerFileBinTor			@"tor"

#define SMTorManagerKeyInfoFiles		@"files"
#define SMTorManagerKeyInfoTorVersion	@"tor_version"
#define SMTorManagerKeyInfoHash			@"hash"

#define SMTorManagerKeyArchiveSize		@"size"
#define SMTorManagerKeyArchiveName		@"name"
#define SMTorManagerKeyArchiveVersion	@"version"
#define SMTorManagerKeyArchiveHash		@"hash"

// Identity
#define SMTorManagerFileIdentityHostname	@"hostname"
#define SMTorManagerFileIdentityPrivate		@"private_key"

// Control
#define SMTorManagerTorControlHostFile	@"tor_ctrl"

// Context
#define SMTorManagerBaseUpdateURL			@"http://www.sourcemac.com/tor/%@"
#define SMTorManagerInfoUpdateURL			@"http://www.sourcemac.com/tor/info.plist"
#define SMTorManagerInfoSignatureUpdateURL	@"http://www.sourcemac.com/tor/info.plist.sig"



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

// Version.
static BOOL	version_greater(NSString * _Nullable baseVersion, NSString * _Nullable newVersion);



/*
** Interfaces
*/
#pragma mark - Interface

#pragma mark SMTorDownloadContext

@interface SMTorDownloadContext : NSObject

// -- Instance --
- (nullable instancetype)initWithPath:(NSString *)path;

// -- Methods --
- (void)handleData:(NSData *)data;
- (void)handleComplete:(NSError *)error;

- (NSData *)sha1;

- (void)close;

// -- Properties --
@property (strong, nonatomic) void (^updateHandler) (SMTorDownloadContext *context, NSUInteger bytesDownloaded, BOOL complete, NSError * _Nullable error);

@end


#pragma mark SMTorTask

@interface SMTorTask : NSObject <NSURLSessionDelegate>

@property (strong, atomic) void (^logHandler)(SMTorManagerLogKind kind, NSString *log);

// -- Life --
- (void)startWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorManagerLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info))handler;
- (void)stopWithCompletionHandler:(nullable dispatch_block_t)handler;

// -- Download Context --
- (void)addDownloadContext:(SMTorDownloadContext *)context forKey:(id <NSCopying>)key;
- (void)removeDownloadContextForKey:(id)key;

@end


#pragma mark SMTorControl

@interface SMTorControl : NSObject <SMSocketDelegate>

@property (strong, atomic) void (^serverEvent)(NSString *type, NSString *content);
@property (strong, atomic) void (^socketError)(SMInfo *info);

// -- Instance --
- (nullable instancetype)initWithIP:(NSString *)ip port:(uint16_t)port;

// -- Life --
- (void)stop;

// -- Commands --
- (void)sendAuthenticationCommandWithKeyHexa:(NSString *)keyHexa resultHandler:(void (^)(BOOL success))handler;
- (void)sendGetInfoCommandWithInfo:(NSString *)info resultHandler:(void (^)(BOOL success, NSString * _Nullable info))handler;
- (void)sendSetEventsCommandWithEvents:(NSString *)events resultHandler:(void (^)(BOOL success))handler;

// -- Helpers --
+ (NSDictionary *)parseNoticeBootstrap:(NSString *)line;

@end


#pragma mark SMTorOperations

@interface SMTorOperations : NSObject

+ (dispatch_block_t)operationRetrieveRemoteInfoWithURLSession:(NSURLSession *)urlSession completionHandler:(void (^)(SMInfo *info))handler;
+ (void)operationStageArchiveFile:(NSURL *)fileURL toTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler;
+ (void)operationCheckSignatureWithTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler;
+ (void)operationLaunchTorWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorManagerLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable ctrlKeyHexa))handler;

@end



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

- (id)initWithConfiguration:(SMTorConfiguration *)configuration
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
						switch ((SMTorManagerEventStart)(info.code))
						{
							case SMTorManagerEventStartURLSession:
							{
								dispatch_async(_localQueue, ^{
									_urlSession = info.context;
								});
								break;
							}
								
							case SMTorManagerEventStartDone:
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
						dispatch_async(_localQueue, ^{
							if (info.code == SMTorManagerWarningStartCanceled)
							{
								_torTask = nil;
								_urlSession = nil;
							}
						});
						
						ctrl(SMOperationsControlContinue);

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
				dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), handler);
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
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoCheckUpdateDomain code:SMTorManagerErrorCheckUpdateTorNotRunning]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			ctrl(SMOperationsControlContinue);
		}];
		
		// -- Retrieve remote info --
		__block NSString *remoteVersion = nil;
		
		[queue scheduleCancelableOnQueue:_localQueue block:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {

			dispatch_block_t cancelHandler;
			
			cancelHandler = [SMTorOperations operationRetrieveRemoteInfoWithURLSession:_urlSession completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoCheckUpdateDomain code:SMTorManagerErrorRetrieveRemoteInfo info:info]);
					ctrl(SMOperationsControlFinish);
				}
				if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationInfo)
					{
						NSDictionary *remoteInfo = info.context;
						
						remoteVersion = remoteInfo[SMTorManagerKeyArchiveVersion];
						
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
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoCheckUpdateDomain code:SMTorManagerErrorCheckUpdateLocalSignature info:info]);
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationInfo)
					{
						localVersion = ((NSDictionary *)info.context)[SMTorManagerKeyInfoTorVersion];
					}
					else if (info.code == SMTorManagerEventOperationDone)
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
				
				handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoCheckUpdateDomain code:SMTorManagerEventCheckUpdateAvailable context:context]);
			}
			else
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoCheckUpdateDomain code:SMTorManagerErrorCheckUpdateNothingNew]);
			
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
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateTorNotRunning]);
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
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateArchiveInfoRetrieving]);
	
			// Retrieve remote informations.
			dispatch_block_t opCancel;

			opCancel = [SMTorOperations operationRetrieveRemoteInfoWithURLSession:_urlSession completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateArchiveInfo info:info]);
					ctrl(SMOperationsControlFinish);
				}
				if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationInfo)
					{
						NSDictionary *remoteInfo = info.context;
						
						remoteName = remoteInfo[SMTorManagerKeyArchiveName];
						remoteHash = remoteInfo[SMTorManagerKeyArchiveHash];
						remoteSize = remoteInfo[SMTorManagerKeyArchiveSize];
						
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
			NSString	*urlString = [NSString stringWithFormat:SMTorManagerBaseUpdateURL, remoteName];
			NSURL		*url = [NSURL URLWithString:urlString];
			
			// Create task.
			NSURLSessionDataTask *task = [_urlSession dataTaskWithURL:url];
			
			// Get download path.
			if (!downloadPath)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateConfiguration]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Create context.
			SMTorDownloadContext *context = [[SMTorDownloadContext alloc] initWithPath:downloadArchivePath];
			
			if (!context)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateInternal]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			context.updateHandler = ^(SMTorDownloadContext *aContext, NSUInteger bytesDownloaded, BOOL complete, NSError *error) {
				
				// > Handle complete.
				if (complete || bytesDownloaded > [remoteSize unsignedIntegerValue])
				{
					if (complete)
					{
						if (error)
						{
							handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateArchiveDownload context:error]);
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
					if ([[aContext sha1] isEqualToData:remoteHash] == NO)
					{
						handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateArchiveDownload context:error]);
						ctrl(SMOperationsControlFinish);
						return;
					}
					
					// > Continue.
					ctrl(SMOperationsControlContinue);
				}
				else
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateArchiveDownloading context:@(bytesDownloaded)]);
			};
			
			// Handle context.
			[_torTask addDownloadContext:context forKey:@(task.taskIdentifier)];
			
			// Resume task.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateArchiveSize context:remoteSize]);
			
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
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateArchiveStage]);
			
			// Stage file.
			[SMTorOperations operationStageArchiveFile:[NSURL fileURLWithPath:downloadArchivePath] toTorBinariesPath:_configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateArchiveStage]);
					ctrl(SMOperationsControlFinish);
					return;
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Check signature --
		[queue scheduleOnQueue:_localQueue block:^(SMOperationsControl ctrl) {
			
			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateSignatureCheck]);
			
			// Check signature.
			[SMTorOperations operationCheckSignatureWithTorBinariesPath:_configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorCheckUpdateLocalSignature info:info]);
					ctrl(SMOperationsControlFinish);
					return;
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationDone)
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
					if (info.code == SMTorManagerEventStartURLSession)
					{
						dispatch_async(_localQueue, ^{
							_urlSession = info.context;
						});
					}
					else if (info.code == SMTorManagerEventStartDone)
					{
						dispatch_async(_localQueue, ^{
							_torTask = torTask;
						});
						
						ctrl(SMOperationsControlContinue);
					}
				}
				else if (info.kind == SMInfoWarning)
				{
					if (info.code == SMTorManagerWarningStartCanceled)
					{
						handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateRelaunch info:info]);
						ctrl(SMOperationsControlFinish);
					}
				}
				else if (info.kind == SMInfoError)
				{
					handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoUpdateDomain code:SMTorManagerErrorUpdateRelaunch info:info]);
					ctrl(SMOperationsControlFinish);
					return;
				}
			}];
			
			addCancelBlock(^{ [torTask stopWithCompletionHandler:nil]; });
		}];
		
		// -- Done --
		[queue scheduleBlock:^(SMOperationsControl ctrl) {

			// Notify step.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoUpdateDomain code:SMTorManagerEventUpdateDone]);
			
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
			
			if ([_configuration.identityPath isEqualToString:configuration.identityPath] == NO)
				[self _moveTorIdentityFilesToPath:configuration.identityPath];
			
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
						if (info.code == SMTorManagerEventStartURLSession)
						{
							dispatch_async(_localQueue, ^{
								_urlSession = info.context;
							});
						}
						else if (info.code == SMTorManagerEventStartDone)
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
						if (info.code == SMTorManagerWarningStartCanceled)
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
	NSString *oldPathSignature = [_configuration.binaryPath stringByAppendingPathComponent:SMTorManagerFileBinSignature];
	NSString *oldPathInfo = [_configuration.binaryPath stringByAppendingPathComponent:SMTorManagerFileBinInfo];
	NSString *oldPathBinaries = [_configuration.binaryPath stringByAppendingPathComponent:SMTorManagerFileBinBinaries];
	
	NSString *newPathSignature = [newBinaryPath stringByAppendingPathComponent:SMTorManagerFileBinSignature];
	NSString *newPathInfo = [newBinaryPath stringByAppendingPathComponent:SMTorManagerFileBinInfo];
	NSString *newPathBinaries = [newBinaryPath stringByAppendingPathComponent:SMTorManagerFileBinBinaries];
	
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

- (void)_moveTorIdentityFilesToPath:(NSString *)newIdentityPath
{
	SMDebugLog(@"~identityPath - move files.");
	
	NSError *error = nil;
	

	// Compose paths.
	NSString *oldPathHostname = [_configuration.identityPath stringByAppendingPathComponent:SMTorManagerFileIdentityHostname];
	NSString *oldPathPrivateKey = [_configuration.identityPath stringByAppendingPathComponent:SMTorManagerFileIdentityPrivate];
	
	NSString *newPathHostname = [newIdentityPath stringByAppendingPathComponent:SMTorManagerFileIdentityHostname];
	NSString *newPathPrivateKey = [newIdentityPath stringByAppendingPathComponent:SMTorManagerFileIdentityPrivate];
	
	// Create target directory.
	if ([[NSFileManager defaultManager] createDirectoryAtPath:newIdentityPath withIntermediateDirectories:YES attributes:nil error:&error] == NO)
	{
		if (error.domain != NSCocoaErrorDomain || error.code != NSFileWriteFileExistsError)
		{
			NSLog(@"Error: Can't create target directory (%@)", error);
			return;
		}
	}
	
	// Move paths.
	if ([[NSFileManager defaultManager] moveItemAtPath:oldPathHostname toPath:newPathHostname error:&error] == NO)
	{
		NSLog(@"Error: Can't move identity file %@", error);
		return;
	}
	
	if ([[NSFileManager defaultManager] moveItemAtPath:oldPathPrivateKey toPath:newPathPrivateKey error:&error] == NO)
	{
		NSLog(@"Error: Can't move private-key file %@", error);
		return;
	}
}



/*
** SMTorManager - Infos
*/
#pragma mark - SMTorManager - Infos

+ (void)registerInfoDescriptors
{
	NSMutableDictionary *descriptors = [[NSMutableDictionary alloc] init];
	
	// == SMTorManagerInfoStartDomain ==
	descriptors[SMTorManagerInfoStartDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {
		
		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorManagerEventStart)code)
				{
					case SMTorManagerEventStartBootstrapping:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventStartBootstrapping",
							SMInfoDynTextKey : ^ NSString *(NSDictionary *context) {
								NSNumber	*progress = context[@"progress"];
								NSString	*summary = context[@"summary"];
									 
								return [NSString stringWithFormat:SMLocalizedString(@"tor_start_info_bootstrap", @""), [progress unsignedIntegerValue], summary];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
					
					case SMTorManagerEventStartHostname:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventStartHostname",
							SMInfoDynTextKey : ^ NSString *(NSString *context) {
								return [NSString stringWithFormat:SMLocalizedString(@"tor_start_info_hostname", @""), context];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
						
					case SMTorManagerEventStartURLSession:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventStartURLSession",
							SMInfoTextKey : @"tor_start_info_url_session",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventStartDone:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventStartDone",
							SMInfoTextKey : @"tor_start_info_done",
							SMInfoLocalizableKey : @YES,
						  };
					}
				}
				break;
			}
				
			case SMInfoWarning:
			{
				switch ((SMTorManagerWarningStart)code)
				{
					case SMTorManagerWarningStartCanceled:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerWarningStartCanceled",
							SMInfoTextKey : @"tor_start_warning_canceled",
							SMInfoLocalizableKey : @YES,
						  };
					}
				}
				break;
			}
			
			case SMInfoError:
			{
				switch ((SMTorManagerErrorStart)code)
				{
					case SMTorManagerErrorStartAlreadyRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartAlreadyRunning",
							SMInfoTextKey : @"tor_start_err_already_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartConfiguration",
							SMInfoTextKey : @"tor_start_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartUnarchive:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartUnarchive",
							SMInfoTextKey : @"tor_start_err_unarchive",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartSignature",
							SMInfoTextKey : @"tor_start_err_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartLaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartLaunch",
							SMInfoTextKey : @"tor_start_err_launch",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartControlConnect:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartControlConnect",
							SMInfoTextKey : @"tor_start_err_control_connect",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartControlAuthenticate:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartControlAuthenticate",
							SMInfoTextKey : @"tor_start_err_control_authenticate",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorStartControlMonitor:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorStartControlMonitor",
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
	
	// == SMTorManagerInfoCheckUpdateDomain ==
	descriptors[SMTorManagerInfoCheckUpdateDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorManagerEventCheckUpdate)code)
				{
					case SMTorManagerEventCheckUpdateAvailable:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventCheckUpdateAvailable",
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
				switch ((SMTorManagerErrorCheckUpdate)code)
				{
					case SMTorManagerErrorCheckUpdateTorNotRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorCheckUpdateTorNotRunning",
							SMInfoTextKey : @"tor_checkupdate_error_not_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorRetrieveRemoteInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorRetrieveRemoteInfo",
							SMInfoTextKey : @"tor_checkupdate_error_check_remote_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorCheckUpdateLocalSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorCheckUpdateLocalSignature",
							SMInfoTextKey : @"tor_checkupdate_error_validate_local_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorCheckUpdateNothingNew:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorCheckUpdateNothingNew",
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
	
	// == SMTorManagerInfoUpdateDomain ==
	descriptors[SMTorManagerInfoUpdateDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorManagerEventUpdate)code)
				{
					case SMTorManagerEventUpdateArchiveInfoRetrieving:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateArchiveInfoRetrieving",
							SMInfoTextKey : @"tor_update_info_retrieve_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventUpdateArchiveSize:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateArchiveSize",
							SMInfoDynTextKey : ^ NSString *(NSNumber *context) {
								return [NSString stringWithFormat:SMLocalizedString(@"tor_update_info_archive_size", @""), [context unsignedLongLongValue]];
							},
							SMInfoLocalizableKey : @NO,
						};
					}
						
					case SMTorManagerEventUpdateArchiveDownloading:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateArchiveDownloading",
							SMInfoTextKey : @"tor_update_info_downloading",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventUpdateArchiveStage:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateArchiveStage",
							SMInfoTextKey : @"tor_update_info_stage",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventUpdateSignatureCheck:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateSignatureCheck",
							SMInfoTextKey : @"tor_update_info_signature_check",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventUpdateRelaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateRelaunch",
							SMInfoTextKey : @"tor_update_info_relaunch",
							SMInfoLocalizableKey : @YES,
							};
					}
						
					case SMTorManagerEventUpdateDone:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventUpdateDone",
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
				switch ((SMTorManagerErrorUpdate)code)
				{
					case SMTorManagerErrorUpdateTorNotRunning:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateTorNotRunning",
							SMInfoTextKey : @"tor_update_err_not_running",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateConfiguration",
							SMInfoTextKey : @"tor_update_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateInternal:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateInternal",
							SMInfoTextKey : @"tor_update_err_internal",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateArchiveInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateArchiveInfo",
							SMInfoTextKey : @"tor_update_err_archive_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateArchiveDownload:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateArchiveDownload",
							SMInfoTextKey : @"tor_update_err_archive_download",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateArchiveStage:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateArchiveStage",
							SMInfoTextKey : @"tor_update_err_archive_stage",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorUpdateRelaunch:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorUpdateRelaunch",
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
	
	// == SMTorManagerInfoOperationDomain ==
	descriptors[SMTorManagerInfoOperationDomain] = ^ NSDictionary * (SMInfoKind kind, int code) {

		switch (kind)
		{
			case SMInfoInfo:
			{
				switch ((SMTorManagerEventOperation)code)
				{
					case SMTorManagerEventOperationInfo:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventOperationInfo",
							SMInfoTextKey : @"tor_operation_info_info",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerEventOperationDone:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerEventOperationDone",
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
				switch ((SMTorManagerErrorOperation)code)
				{
					case SMTorManagerErrorOperationConfiguration:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationConfiguration",
							SMInfoTextKey : @"tor_operation_err_configuration",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorOperationIO:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationIO",
							SMInfoTextKey : @"tor_operation_err_io",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorOperationNetwork:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationNetwork",
							SMInfoTextKey : @"tor_operation_err_network",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorOperationExtract:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationExtract",
							SMInfoTextKey : @"tor_operation_err_extract",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorOperationSignature:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationSignature",
							SMInfoTextKey : @"tor_operation_err_signature",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorOperationTor:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorOperationTor",
							SMInfoTextKey : @"tor_operation_err_tor",
							SMInfoLocalizableKey : @YES,
						};
					}
						
					case SMTorManagerErrorInternal:
					{
						return @{
							SMInfoNameKey : @"SMTorManagerErrorInternal",
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

- (void)startWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorManagerLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info))handler
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
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartURLSession context:_torURLSession]);
					
					// Say ready.
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartDone]);
					
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
			
			path = [[configuration.binaryPath stringByAppendingPathComponent:SMTorManagerFileBinBinaries] stringByAppendingPathComponent:SMTorManagerFileBinTor];
			
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
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartUnarchive info:info];
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationDone)
						ctrl(SMOperationsControlContinue);
				}
			}];
		}];
		
		// -- Check signature --
		[operations scheduleBlock:^(SMOperationsControl ctrl) {
			
			[SMTorOperations operationCheckSignatureWithTorBinariesPath:configuration.binaryPath completionHandler:^(SMInfo *info) {
				
				if (info.kind == SMInfoError)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartSignature info:info];
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationDone)
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
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartLaunch info:info];
					ctrl(SMOperationsControlFinish);
				}
				else if (info.kind == SMInfoInfo)
				{
					if (info.code == SMTorManagerEventOperationDone)
					{
						ctrlKeyHexa = aCtrlKeyHexa;
						
						dispatch_async(_localQueue, ^{
							_task = task;
						});
						
						ctrl(SMOperationsControlContinue);
					}
				}
			}];
		}];
		
		// -- Wait identity --
		if (configuration.hiddenService)
		{
			[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
				
				// Get the hostname file path.
				NSString *htnamePath = [configuration.identityPath stringByAppendingPathComponent:SMTorManagerFileIdentityHostname];
				
				if (!htnamePath)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartConfiguration];
					ctrl(SMOperationsControlFinish);
					return;
				}
				
				// Wait for file appearance.
				dispatch_source_t testTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _localQueue);
				
				dispatch_source_set_timer(testTimer, DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC, 0);
				
				dispatch_source_set_event_handler(testTimer, ^{
					
					// Try to read file.
					NSString *hostname = [NSString stringWithContentsOfFile:htnamePath encoding:NSASCIIStringEncoding error:nil];
					
					if (!hostname)
						return;
					
					// Extract first part.
					NSRange rg = [hostname rangeOfString:@".onion"];
					
					if (rg.location == NSNotFound)
						return;
					
					NSString *hidden = [hostname substringToIndex:rg.location];
					
					// Flag as running.
					_isRunning = YES;
					
					// Stop ourself.
					dispatch_source_cancel(testTimer);
					
					// Notify user.
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartHostname context:hidden]);
					
					// Continue.
					ctrl(SMOperationsControlContinue);
				});
				
				// Start timer
				dispatch_resume(testTimer);
				
				// Set cancelation.
				addCancelBlock(^{
					SMDebugLog(@"<cancel startWithBinariesPath (Wait hostname)>");
					dispatch_source_cancel(testTimer);
				});
			}];
		}
		
		// -- Wait control info --
		__block NSString *torCtrlAddress = nil;
		__block NSString *torCtrlPort = nil;

		[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {
			
			// Get the hostname file path.
			NSString *ctrlInfoPath = [configuration.dataPath stringByAppendingPathComponent:SMTorManagerTorControlHostFile];
			
			if (!ctrlInfoPath)
			{
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartConfiguration];
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
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartControlConnect];
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Authenticate control.
			[control sendAuthenticationCommandWithKeyHexa:ctrlKeyHexa resultHandler:^(BOOL success) {
				
				if (!success)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartControlAuthenticate];
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
		
		// -- Wait for bootstrap completion --
		[operations scheduleCancelableBlock:^(SMOperationsControl ctrl, SMOperationsAddCancelBlock addCancelBlock) {

			// Check that we have a control.
			if (!control)
			{
				errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartControlMonitor];
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
					handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartBootstrapping context:@{ @"progress" : progress, @"summary" : summary }]);
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
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartControlMonitor];
					ctrl(SMOperationsControlFinish);
					return;
				}
			}];
			
			// Ask current status (because if we tor is already bootstrapped, we are not going to receive other bootstrap events).
			[control sendGetInfoCommandWithInfo:@"status/bootstrap-phase" resultHandler:^(BOOL success, NSString * _Nullable info) {
				
				if (!success)
				{
					errorInfo = [SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoStartDomain code:SMTorManagerErrorStartControlMonitor];
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
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartURLSession context:urlSession]);
			
			// Continue.
			ctrl(SMOperationsControlContinue);
		}];
		
		
		// -- Finish --
		operations.finishHandler = ^(BOOL canceled){

			// Handle error & cancelation.
			if (errorInfo || canceled)
			{
				if (canceled)
					handler([SMInfo infoOfKind:SMInfoWarning domain:SMTorManagerInfoStartDomain code:SMTorManagerWarningStartCanceled]);
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
				handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoStartDomain code:SMTorManagerEventStartDone]);
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



/*
** SMTorControl
*/
#pragma mark - SMTorControl

@implementation SMTorControl
{
	dispatch_queue_t _localQueue;
	
	SMSocket *_socket;
	
	NSMutableArray *_handlers;
	
	NSRegularExpression *_regexpEvent;
}


/*
** SMTorControl - Instance
*/
#pragma mark - SMTorControl - Instance

- (nullable instancetype)initWithIP:(NSString *)ip port:(uint16_t)port
{
	self = [super init];
	
	if (self)
	{
		NSAssert(ip, @"ip is nil");
		
		// Queues.
		_localQueue = dispatch_queue_create("com.smtor.tor-control.local", DISPATCH_QUEUE_SERIAL);
		
		// Socket.
		_socket = [[SMSocket alloc] initWithIP:ip port:port];
		
		if (!_socket)
			return nil;
		
		_socket.delegate = self;
		
		[_socket setGlobalOperation:SMSocketOperationLine withSize:0 andTag:0];
		
		// Containers.
		_handlers = [[NSMutableArray alloc] init];
		
		// Regexp.
		_regexpEvent = [NSRegularExpression regularExpressionWithPattern:@"([A-Za-z0-9_]+) (.*)" options:0 error:nil];
	}
	
	return self;
}

- (void)dealloc
{
	SMDebugLog(@"SMTorControl dealloc");
}



/*
** SMTorControl - Life
*/
#pragma mark - SMTorControl - Life

- (void)stop
{
	dispatch_async(_localQueue, ^{
		
		// Stop socket.
		[_socket stop];
		
		// Finish handler.
		for (void (^handler)(NSNumber *code, NSString * _Nullable line) in _handlers)
			handler(@(551), nil);
		
		[_handlers removeAllObjects];
	});
}



/*
** SMTorControl - Commands
*/
#pragma mark - SMTorControl - Commands

- (void)sendAuthenticationCommandWithKeyHexa:(NSString *)keyHexa resultHandler:(void (^)(BOOL success))handler
{
	NSAssert(keyHexa, @"keyHexa is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{
		
		NSData *command = [[NSString stringWithFormat:@"AUTHENTICATE %@\n", keyHexa] dataUsingEncoding:NSASCIIStringEncoding];
		
		[_handlers addObject:^(NSNumber *code, NSString * _Nullable line) {
			handler([code integerValue] == 250);
		}];
		
		[_socket sendBytes:command.bytes ofSize:command.length copy:YES];
	});
}

- (void)sendGetInfoCommandWithInfo:(NSString *)info resultHandler:(void (^)(BOOL success, NSString * _Nullable info))handler
{
	NSAssert(info, @"info is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{

		NSData *command = [[NSString stringWithFormat:@"GETINFO %@\n", info] dataUsingEncoding:NSASCIIStringEncoding];
		
		[_handlers addObject:^(NSNumber *code, NSString * _Nullable line) {
			
			// Check code.
			if ([code integerValue] != 250)
			{
				handler(NO, nil);
				return;
			}
			
			// Check prefix.
			NSString *prefix = [NSString stringWithFormat:@"-%@=", info];
			
			if ([line hasPrefix:prefix] == NO)
			{
				handler(NO, nil);
				return;
			}
			
			// Give content.
			NSString *content = [line substringFromIndex:prefix.length];
			
			handler(YES, content);
		}];
		
		[_socket sendBytes:command.bytes ofSize:command.length copy:YES];
	});
}

- (void)sendSetEventsCommandWithEvents:(NSString *)events resultHandler:(void (^)(BOOL success))handler
{
	NSAssert(events, @"events is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{

		NSData *command = [[NSString stringWithFormat:@"SETEVENTS %@\n", events] dataUsingEncoding:NSASCIIStringEncoding];
		
		[_handlers addObject:^(NSNumber *code, NSString * _Nullable line) {
			handler([code integerValue] == 250);
		}];
		
		[_socket sendBytes:command.bytes ofSize:command.length copy:YES];
	});
}



/*
** SMTorControl - Helpers
*/
#pragma mark - SMTorControl - Helpers

+ (NSDictionary *)parseNoticeBootstrap:(NSString *)line
{
	NSAssert(line, @"line is nil");
	
	// Create regexp.
	static dispatch_once_t		onceToken;
	static NSRegularExpression	*regexp;
	
	dispatch_once(&onceToken, ^{
		regexp = [NSRegularExpression regularExpressionWithPattern:@"NOTICE BOOTSTRAP PROGRESS=([0-9]+) TAG=([A-Za-z0-9_]+) SUMMARY=\"(.*)\"" options:0 error:nil];
	});
	
	// Parse.
	NSArray<NSTextCheckingResult *> *matches = [regexp matchesInString:line options:0 range:NSMakeRange(0, line.length)];
	
	if (matches.count != 1)
		return nil;
	
	NSTextCheckingResult *match = [matches firstObject];
	
	if ([match numberOfRanges] != 4)
		return nil;
	
	// Extract.
	NSString *progress = [line substringWithRange:[match rangeAtIndex:1]];
	NSString *tag = [line substringWithRange:[match rangeAtIndex:2]];
	NSString *summary = [line substringWithRange:[match rangeAtIndex:3]];
	
	return @{ @"progress" : @([progress integerValue]), @"tag" : tag, @"summary" : [summary stringByReplacingOccurrencesOfString:@"\\\"" withString:@"\""] };
}



/*
** SMTorControl - SMSocketDelegate
*/
#pragma mark - SMTorControl - SMSocketDelegate

- (void)socket:(SMSocket *)socket operationAvailable:(SMSocketOperation)operation tag:(NSUInteger)tag content:(id)content
{
	dispatch_async(_localQueue, ^{
	
		NSArray *lines = content;
		
		for (NSData *line in lines)
		{
			NSString *lineStr = [[[NSString alloc] initWithData:line encoding:NSASCIIStringEncoding] stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]];
			
			if (lineStr.length < 3)
				continue;
			
			NSString	*code = [lineStr substringWithRange:NSMakeRange(0, 3)];
			NSInteger	codeValue = [code integerValue];
			
			if (codeValue <= 0)
				continue;
			
			NSString *info = [[lineStr substringFromIndex:3] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
			
			// Handle events.
			if (codeValue == 650)
			{
				// > Get event handler.
				void (^serverEvent)(NSString *type, NSString *content) = self.serverEvent;
				
				if (!serverEvent)
					continue;
				
				// > Parse event structure.
				NSArray<NSTextCheckingResult *> *matches = [_regexpEvent matchesInString:info options:0 range:NSMakeRange(0, info.length)];
				
				if (matches.count != 1)
					continue;
				
				NSTextCheckingResult *match = [matches firstObject];
				
				if (match.numberOfRanges != 3)
					continue;
				
				NSString *type = [info substringWithRange:[match rangeAtIndex:1]];
				NSString *finfo = [info substringWithRange:[match rangeAtIndex:2]];
				
				// > Notify event.
				serverEvent(type, finfo);
			}
			// Handle common reply.
			else
			{
				// Get handler.
				if ([_handlers count] == 0)
					continue;
				
				void (^handler)(NSNumber *code, NSString * _Nullable line) = [_handlers firstObject];
				
				[_handlers removeObjectAtIndex:0];
				
				// Give content.
				handler(@(codeValue), info);
			}
			
		}
	});
}

- (void)socket:(SMSocket *)socket error:(SMInfo *)error
{
	// Finish handlers.
	dispatch_async(_localQueue, ^{
		for (void (^handler)(NSNumber *code, NSString * _Nullable line) in _handlers)
			handler(@(551), nil);
		
		[_handlers removeAllObjects];
	});
		
	// Notify error.
	void (^socketError)(SMInfo *info) = self.socketError;
	
	if (!socketError)
		return;
	
	socketError(error);
}

@end



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
		NSURL					*url = [NSURL URLWithString:SMTorManagerInfoUpdateURL];
		NSURLSessionDataTask	*task;
		
		task = [urlSession dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
			
			// Check error.
			if (error)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationNetwork context:error]);
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
		NSURL					*url = [NSURL URLWithString:SMTorManagerInfoSignatureUpdateURL];
		NSURLSessionDataTask	*task;
		
		task = [urlSession dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
			
			// Check error.
			if (data.length == 0 || error)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationNetwork context:error]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Check content.
			NSData *publicKey = [[NSData alloc] initWithBytesNoCopy:(void *)kPublicKey length:sizeof(kPublicKey) freeWhenDone:NO];
			
			if ([SMDataSignature validateSignature:data forData:remoteInfoData withPublicKey:publicKey] == NO)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationSignature context:error]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Parse content.
			NSError *pError = nil;
			
			remoteInfo = [NSPropertyListSerialization propertyListWithData:remoteInfoData options:NSPropertyListImmutable format:nil error:&pError];
			
			if (!remoteInfo)
			{
				handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorInternal context:pError]);
				ctrl(SMOperationsControlFinish);
				return;
			}
			
			// Give result.
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationInfo context:remoteInfo]);
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationDone context:remoteInfo]);
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
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorInternal]);
		return;
	}
	
	NSFileManager *fileManager = [NSFileManager defaultManager];
	
	// Get target directory.
	if ([torBinPath hasSuffix:@"/"])
		torBinPath = [torBinPath substringToIndex:([torBinPath length] - 1)];
	
	if (!torBinPath)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationIO]);
		return;
	}
	
	// Create target directory.
	if ([fileManager createDirectoryAtPath:torBinPath withIntermediateDirectories:YES attributes:nil error:nil] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationConfiguration]);
		return;
	}
	
	// Copy tarball.
	NSString *filePath = [fileURL path];
	NSString *newFilePath = [torBinPath stringByAppendingPathComponent:@"_temp.tgz"];
	
	[fileManager removeItemAtPath:newFilePath error:nil];
	
	if (!filePath || [fileManager copyItemAtPath:filePath toPath:newFilePath error:nil] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationIO]);
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
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationExtract context:@([aTask terminationStatus])]);
		else
			handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationDone]);
		
		[fileManager removeItemAtPath:newFilePath error:nil];
	};
	
	@try {
		[task launch];
	}
	@catch (NSException *exception) {
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationExtract context:@(-1)]);
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
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationConfiguration]);
		return;
	}
	
	// Build paths.
	NSString *signaturePath = [torBinPath stringByAppendingPathComponent:SMTorManagerFileBinSignature];
	NSString *binariesPath = [torBinPath stringByAppendingPathComponent:SMTorManagerFileBinBinaries];
	NSString *infoPath = [torBinPath stringByAppendingPathComponent:SMTorManagerFileBinInfo];
	
	// Read signature.
	NSData *data = [NSData dataWithContentsOfFile:signaturePath];
	
	if (data.length == 0)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationIO]);
		return;
	}
	
	// Check signature.
	NSData *publicKey = [[NSData alloc] initWithBytesNoCopy:(void *)kPublicKey length:sizeof(kPublicKey) freeWhenDone:NO];
	
	if ([SMFileSignature validateSignature:data forContentsOfURL:[NSURL fileURLWithPath:infoPath] withPublicKey:publicKey] == NO)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationSignature context:infoPath]);
		return;
	}
	
	// Read info.plist.
	NSData			*infoData = [NSData dataWithContentsOfFile:infoPath];
	NSDictionary	*info = [NSPropertyListSerialization propertyListWithData:infoData options:NSPropertyListImmutable format:nil error:nil];
	
	if (!info)
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationIO]);
		return;
	}
	
	// Give info.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationInfo context:info]);
	
	// Check files hash.
	NSDictionary *files = info[SMTorManagerKeyInfoFiles];
	
	for (NSString *file in files)
	{
		NSString		*filePath = [binariesPath stringByAppendingPathComponent:file];
		NSDictionary	*fileInfo = files[file];
		NSData			*infoHash = fileInfo[SMTorManagerKeyInfoHash];
		NSData			*diskHash = file_sha1([NSURL fileURLWithPath:filePath]);
		
		if (!diskHash || [infoHash isEqualToData:diskHash] == NO)
		{
			handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationSignature context:filePath]);
			return;
		}
	}
	
	// Finish.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationDone]);
}

+ (void)operationLaunchTorWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorManagerLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable ctrlKeyHexa))handler
{
	NSAssert(handler, @"handler is nil");
	
	// Check configuration.
	NSString *binaryPath = configuration.binaryPath;
	NSString *dataPath = configuration.dataPath;
	NSString *identityPath = configuration.identityPath;
	
	if (!binaryPath || !dataPath || (configuration.hiddenService && identityPath == nil))
	{
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationConfiguration], nil, nil);
		return;
	}
	
	SMDebugLog(@"~~~~~ launch-tor");
	SMDebugLog(@"_torBinPath '%@'", binaryPath);
	SMDebugLog(@"_torDataPath '%@'", dataPath);
	SMDebugLog(@"_torIdentityPath '%@'", identityPath);
	SMDebugLog(@"-----");
	
	// Create directories.
	NSFileManager *mng = [NSFileManager defaultManager];
	
	[mng createDirectoryAtPath:dataPath withIntermediateDirectories:NO attributes:nil error:nil];
	[mng createDirectoryAtPath:identityPath withIntermediateDirectories:NO attributes:nil error:nil];
	
	[mng setAttributes:@{ NSFilePosixPermissions : @(0700) } ofItemAtPath:dataPath error:nil];
	[mng setAttributes:@{ NSFilePosixPermissions : @(0700) } ofItemAtPath:identityPath error:nil];
	
	// Clean previous file.
	[mng removeItemAtPath:[dataPath stringByAppendingPathComponent:SMTorManagerTorControlHostFile] error:nil];
	
	// Create control password.
	NSMutableData	*ctrlPassword = [[NSMutableData alloc] initWithLength:32];
	NSString		*hashedPassword;
	NSString		*hexaPassword;
	
	arc4random_buf(ctrlPassword.mutableBytes, ctrlPassword.length);
	
	hashedPassword = s2k_from_data(ctrlPassword, 96);
	hexaPassword = hexa_from_data(ctrlPassword);
	
	// Log snippet.
	dispatch_queue_t logQueue = dispatch_queue_create("com.smtor.tor-task.output", DISPATCH_QUEUE_SERIAL);
	
	void (^handleLog)(NSFileHandle *, SMBuffer *buffer, SMTorManagerLogKind) = ^(NSFileHandle *handle, SMBuffer *buffer, SMTorManagerLogKind kind) {
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
		
		errHandle.readabilityHandler = ^(NSFileHandle *handle) { handleLog(handle, errBuffer, SMTorManagerLogError); };
		outHandle.readabilityHandler = ^(NSFileHandle *handle) { handleLog(handle, outBuffer, SMTorManagerLogStandard); };
		
		[task setStandardError:errPipe];
		[task setStandardOutput:outPipe];
	}
	
	// > Set launch path.
	NSString *torExecPath = [[binaryPath stringByAppendingPathComponent:SMTorManagerFileBinBinaries] stringByAppendingPathComponent:SMTorManagerFileBinTor];
	
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
	
	if (configuration.hiddenService)
	{
		[args addObject:@"--HiddenServiceDir"];
		[args addObject:identityPath];
		
		[args addObject:@"--HiddenServicePort"];
		[args addObject:[NSString stringWithFormat:@"%u %@:%u", configuration.hiddenServiceRemotePort, configuration.hiddenServiceLocalHost, configuration.hiddenServiceLocalPort]];
	}
	
	[args addObject:@"--ControlPort"];
	[args addObject:@"auto"];
	
	[args addObject:@"--ControlPortWriteToFile"];
	[args addObject:[dataPath stringByAppendingPathComponent:SMTorManagerTorControlHostFile]];
	
	[args addObject:@"--HashedControlPassword"];
	[args addObject:hashedPassword];
	
	[task setArguments:args];
	
	
	// Run tor task.
	@try {
		[task launch];
	} @catch (NSException *exception) {
		handler([SMInfo infoOfKind:SMInfoError domain:SMTorManagerInfoOperationDomain code:SMTorManagerErrorOperationTor context:@(-1)], nil, nil);
		return;
	}
	
	// Notify the launch.
	handler([SMInfo infoOfKind:SMInfoInfo domain:SMTorManagerInfoOperationDomain code:SMTorManagerEventOperationDone], task, hexaPassword);
}

@end



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
		
		if (i < [baseParts count])
			baseValue = (NSUInteger)[baseParts[i] intValue];
		
		if (i < [newParts count])
			newValue = (NSUInteger)[newParts[i] intValue];
		
		if (newValue > baseValue)
			return YES;
		else if (newValue < baseValue)
			return NO;
	}
	
	return NO;
}


NS_ASSUME_NONNULL_END
