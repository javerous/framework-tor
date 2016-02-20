/*
 *  SMTorUpdateWindowController.m
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

@import SMFoundation;

#import "SMTorUpdateWindowController.h"

#import "SMTorManager.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorUpdateWindowController - Private
*/
#pragma mark - SMTorUpdateWindowController - Private

@interface SMTorUpdateWindowController ()
{
	SMTorManager		*_torManager;
	
	dispatch_block_t	_currentCancelBlock;
	BOOL				_updateDone;
	
	void (^_infoHandler)(SMInfo *info);
}

@property (strong, nonatomic)	IBOutlet NSView			*availableView;
@property (strong, nonatomic)	IBOutlet NSTextField	*subtitleField;

@property (strong, nonatomic)	IBOutlet NSView			*workingView;
@property (strong, nonatomic)	IBOutlet NSTextField	*workingStatusField;
@property (strong, nonatomic)	IBOutlet NSProgressIndicator *workingProgress;
@property (strong, nonatomic)	IBOutlet NSTextField	*workingDownloadInfo;
@property (strong, nonatomic)	IBOutlet NSButton		*workingButton;


- (IBAction)doRemindMeLater:(id)sender;
- (IBAction)doInstallUpdate:(id)sender;

- (IBAction)doWorkingButton:(id)sender;

@end



/*
** SMTorUpdateWindowController
*/
#pragma mark - SMTorUpdateWindowController

@implementation SMTorUpdateWindowController


/*
** SMTorUpdateWindowController - Instance
*/
#pragma mark - SMTorUpdateWindowController - Instance

+ (instancetype)sharedController
{
	static dispatch_once_t			onceToken;
	static SMTorUpdateWindowController	*instance = nil;
	
	dispatch_once(&onceToken, ^{
		instance = [[SMTorUpdateWindowController alloc] init];
	});
	
	return instance;
}

- (id)init
{
	self = [super initWithWindowNibName:@"UpdateWindow"];
	
	if (self)
	{
	}
	
	return self;
}

- (void)windowDidLoad
{
    [super windowDidLoad];
	
	// Place Window
	[self.window center];
}



/*
** Tools
*/
#pragma mark - Tools

- (void)handleUpdateWithTorManager:(SMTorManager *)torManager oldVersion:(NSString *)oldVersion newVersion:(NSString *)newVersion infoHandler:(nullable void (^)(SMInfo *info))handler
{
	if (!oldVersion || !newVersion || !torManager)
		return;
	
	dispatch_async(dispatch_get_main_queue(), ^{
		
		// Handle tor manager.
		_torManager = torManager;
		
		// Handle log handler.
		dispatch_queue_t logQueue = dispatch_queue_create("com.smtor.update.logs", DISPATCH_QUEUE_SERIAL);
		
		_infoHandler = ^(SMInfo *info) {
			if (handler)
			{
				dispatch_async(logQueue, ^{
					handler(info);
				});
			}
		};
		
		// Place availableView.
		[_workingView removeFromSuperview];
		
		_availableView.alphaValue = 1.0;
		_workingView.alphaValue = 0.0;
		
		[self.window.contentView addSubview:_availableView];
		
		// Configure available view.
		NSString *subtitle = [NSString stringWithFormat:SMLocalizedString(@"update_subtitle_available", @""), newVersion, oldVersion];
		
		_subtitleField.stringValue = subtitle;
		
		// Show window.
		[self showWindow:nil];
	});
}

- (void)_doUpdate
{
	// > main queue <
	
	// Init view state.
	_workingStatusField.stringValue = SMLocalizedString(@"update_status_launching", @"");
	
	_workingDownloadInfo.stringValue = @"";
	_workingDownloadInfo.hidden = YES;
	
	_workingProgress.doubleValue = 0.0;
	_workingProgress.indeterminate = YES;
	_workingProgress.hidden = NO;
	[_workingProgress startAnimation:nil];
	
	_workingButton.title = SMLocalizedString(@"update_button_cancel", @"");
	_workingButton.keyEquivalent = @"\e";
	
	_updateDone = NO;
	
	// Launch update.
	__block NSUInteger		archiveTotal = 0;
	__block NSUInteger		archiveCurrent  = 0;
	__block SMSpeedHelper	*speedHelper = nil;
	__block	double			lastTimestamp = 0.0;
	__block	BOOL			loggedDownload = NO;

	// UI update snippet.
	void (^updateDownloadProgressMessage)(NSTimeInterval) = ^(NSTimeInterval remainingTime){
		// > main queue <
		NSString *currentStr = SMStringFromBytesAmount(archiveCurrent);
		NSString *totalStr = SMStringFromBytesAmount(archiveTotal);
		NSString *str = @"";
		
		if (remainingTime == -2.0)
			str = [NSString stringWithFormat:SMLocalizedString(@"update_download_progress", @""), currentStr, totalStr];
		else if (remainingTime == -1.0)
			str = [NSString stringWithFormat:SMLocalizedString(@"update_download_progress_stalled", @""), currentStr, totalStr];
		else if (remainingTime > 0.0)
			str = [NSString stringWithFormat:SMLocalizedString(@"update_download_progress_remaining", @""), currentStr, totalStr, SMStringFromSecondsAmount(remainingTime)];
		
		_workingDownloadInfo.stringValue = str;
	};
	
	// Launch update.
	_currentCancelBlock = [_torManager updateWithInfoHandler:^(SMInfo *info){
		
		dispatch_async(dispatch_get_main_queue(), ^{
			
			if (info.kind == SMInfoInfo)
			{
				switch ((SMTorManagerEventUpdate)info.code)
				{
					case SMTorManagerEventUpdateArchiveInfoRetrieving:
					{
						// Log
						_infoHandler(info);

						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_retrieving_info", @"");
						
						break;
					}
						
					case SMTorManagerEventUpdateArchiveSize:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_downloading_archive", @"");

						_workingProgress.indeterminate = NO;
						_workingDownloadInfo.hidden = NO;

						archiveTotal = [info.context unsignedIntegerValue];
						
						// Create speed helper.
						speedHelper = [[SMSpeedHelper alloc] initWithCompleteAmount:archiveTotal];
						
						speedHelper.updateHandler = ^(NSTimeInterval remainingTime) {
							dispatch_async(dispatch_get_main_queue(), ^{
								updateDownloadProgressMessage(remainingTime);
							});
						};
						break;
					}
					
					case SMTorManagerEventUpdateArchiveDownloading:
					{
						// Log.
						if (loggedDownload == NO)
						{
							_infoHandler(info);
							loggedDownload = YES;
						}
						
						// Update speed computation.
						archiveCurrent = [info.context unsignedIntegerValue];

						[speedHelper setCurrentAmount:archiveCurrent];

						// Update UI (throttled).
						if (SMTimeStamp() - lastTimestamp > 0.2)
						{
							updateDownloadProgressMessage([speedHelper remainingTime]);
							
							lastTimestamp = SMTimeStamp();
						}
						
						_workingProgress.doubleValue = (double)archiveCurrent / (double)archiveTotal;
						
						// Handle download termination.
						if (archiveCurrent == archiveTotal)
						{
							_workingProgress.indeterminate = YES;
							_workingDownloadInfo.hidden = YES;
							speedHelper = nil;
						}
						
						break;
					}
						
					case SMTorManagerEventUpdateArchiveStage:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_staging_archive", @"");
						
						break;
					}
					
					case SMTorManagerEventUpdateSignatureCheck:
					{
						// Log.
						_infoHandler(info);
						
						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_checking_signature", @"");
						
						break;
					}
						
					case SMTorManagerEventUpdateRelaunch:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_relaunching_tor", @"");
						
						break;
					}
						
					case SMTorManagerEventUpdateDone:
					{
						// Log.
						_infoHandler(info);
						
						// Update UI.
						_workingStatusField.stringValue = SMLocalizedString(@"update_status_update_done", @"");
						
						_workingButton.title = SMLocalizedString(@"update_button_done", @"");
						_workingButton.keyEquivalent = @"\r";
						
						_updateDone = YES;

						break;
					}
				}
			}
			else if (info.kind == SMInfoError)
			{
				speedHelper = nil;

				// Log.
				_infoHandler(info);
				
				// Update UI.
				_workingProgress.hidden = YES;

				_workingDownloadInfo.stringValue = [NSString stringWithFormat:SMLocalizedString(@"update_error_fmt", @""), [info renderMessage]];
				_workingDownloadInfo.hidden = NO;

				_workingStatusField.stringValue = SMLocalizedString(@"update_status_error", @"");
				_workingButton.title = SMLocalizedString(@"update_button_close", @"");
			}
		});
	}];
}



/*
** SMTorUpdateWindowController - IBAction
*/
#pragma mark - SMTorUpdateWindowController - IBAction

- (IBAction)doRemindMeLater:(id)sender
{
	[self close];
}

- (IBAction)doInstallUpdate:(id)sender
{
	// Compute new rect.
	NSSize oldSize = [_availableView frame].size;
	NSSize newSize = [_workingView frame].size;
	
	NSRect frame = [self.window frame];
	NSRect rect;

	rect.size = NSMakeSize(frame.size.width + (newSize.width - oldSize.width), frame.size.height + (newSize.height - oldSize.height));
	rect.origin = NSMakePoint(frame.origin.x + (frame.size.width - rect.size.width) / 2.0, frame.origin.y + (frame.size.height - rect.size.height) / 2.0);

	_availableView.alphaValue = 1.0;
	_workingView.alphaValue = 0.0;
	
	[self.window.contentView addSubview:_workingView];

	[NSAnimationContext runAnimationGroup:^(NSAnimationContext *context) {
		context.duration = 0.1;
		_availableView.animator.alphaValue = 0.0;
		_workingView.animator.alphaValue = 1.0;
		[self.window.animator setFrame:rect display:YES];
	} completionHandler:^{
		[_availableView removeFromSuperview];
		[self _doUpdate];
	}];
}

- (IBAction)doWorkingButton:(id)sender
{
	if (!_updateDone && _currentCancelBlock)
		_currentCancelBlock();
	
	_currentCancelBlock = nil;
	
	[self close];
}

@end


NS_ASSUME_NONNULL_END
