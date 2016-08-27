/*
 *  SMTorUpdateController.m
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

#import "SMTorUpdateController.h"

#import "SMTorManager.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorUpdateWindowController - Interface
*/
#pragma mark - SMTorUpdateWindowController - Interface

@interface SMTorUpdateWindowController : NSWindowController

- (void)handleUpdateWithTorManager:(SMTorManager *)torManager oldVersion:(NSString *)oldVersion newVersion:(NSString *)newVersion infoHandler:(nullable void (^)(SMInfo *info))handler;

@end



/*
** SMTorUpdateController
*/
#pragma mark - SMTorUpdateController

@implementation SMTorUpdateController

+ (void)handleUpdateWithTorManager:(SMTorManager *)torManager oldVersion:(NSString *)oldVersion newVersion:(NSString *)newVersion infoHandler:(nullable void (^)(SMInfo *info))handler
{
	SMTorUpdateWindowController *ctrl = [[SMTorUpdateWindowController alloc] init];

	[ctrl handleUpdateWithTorManager:torManager oldVersion:oldVersion newVersion:newVersion infoHandler:handler];
}

@end



/*
** SMTorUpdateWindowController
*/
#pragma mark - SMTorUpdateWindowController

@implementation SMTorUpdateWindowController
{
	IBOutlet NSView			*availableView;
	IBOutlet NSTextField	*subtitleField;
	
	IBOutlet NSView					*workingView;
	IBOutlet NSTextField			*workingStatusField;
	IBOutlet NSProgressIndicator	*workingProgress;
	IBOutlet NSTextField			*workingDownloadInfo;
	IBOutlet NSButton				*workingButton;
	
	SMTorManager		*_torManager;
	
	dispatch_block_t	_currentCancelBlock;
	BOOL				_updateDone;
	
	void (^_infoHandler)(SMInfo *info);
	
	SMTorUpdateWindowController *_selfRetain;
}


/*
** SMTorUpdateWindowController - Instance
*/
#pragma mark - SMTorUpdateWindowController - Instance

- (instancetype)init
{
	self = [super initWithWindowNibName:@"UpdateWindow"];
	
	if (self)
	{
		_selfRetain = self;
	}
	
	return self;
}

- (void)dealloc
{
	//NSLog(@"SMTorUpdateWindowController dealloc");
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
	NSAssert(oldVersion, @"oldVersion is nil");
	NSAssert(newVersion, @"newVersion is nil");
	NSAssert(torManager, @"torManager is nil");
	
	dispatch_async(dispatch_get_main_queue(), ^{
		
		// Open window.
		[self showWindow:nil];
		
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
		[workingView removeFromSuperview];
		
		availableView.alphaValue = 1.0;
		workingView.alphaValue = 0.0;
		
		[self.window.contentView addSubview:availableView];
		
		// Configure available view.
		NSString *subtitle = [NSString stringWithFormat:SMLocalizedString(@"update_subtitle_available", @""), newVersion, oldVersion];
		
		subtitleField.stringValue = subtitle;
		
		// Show window.
		[self showWindow:nil];
	});
}

- (void)_doUpdate
{
	// > main queue <
	
	// Init view state.
	workingStatusField.stringValue = SMLocalizedString(@"update_status_launching", @"");
	
	workingDownloadInfo.stringValue = @"";
	workingDownloadInfo.hidden = YES;
	
	workingProgress.doubleValue = 0.0;
	workingProgress.indeterminate = YES;
	workingProgress.hidden = NO;
	[workingProgress startAnimation:nil];
	
	workingButton.title = SMLocalizedString(@"update_button_cancel", @"");
	workingButton.keyEquivalent = @"\e";
	
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
		
		workingDownloadInfo.stringValue = str;
	};
	
	// Launch update.
	_currentCancelBlock = [_torManager updateWithInfoHandler:^(SMInfo *info){
		
		dispatch_async(dispatch_get_main_queue(), ^{
			
			if (info.kind == SMInfoInfo)
			{
				switch ((SMTorEventUpdate)info.code)
				{
					case SMTorEventUpdateArchiveInfoRetrieving:
					{
						// Log
						_infoHandler(info);

						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_retrieving_info", @"");
						
						break;
					}
						
					case SMTorEventUpdateArchiveSize:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_downloading_archive", @"");

						workingProgress.indeterminate = NO;
						workingDownloadInfo.hidden = NO;

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
					
					case SMTorEventUpdateArchiveDownloading:
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
						
						workingProgress.doubleValue = (double)archiveCurrent / (double)archiveTotal;
						
						// Handle download termination.
						if (archiveCurrent == archiveTotal)
						{
							workingProgress.indeterminate = YES;
							workingDownloadInfo.hidden = YES;
							speedHelper = nil;
						}
						
						break;
					}
						
					case SMTorEventUpdateArchiveStage:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_staging_archive", @"");
						
						break;
					}
					
					case SMTorEventUpdateSignatureCheck:
					{
						// Log.
						_infoHandler(info);
						
						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_checking_signature", @"");
						
						break;
					}
						
					case SMTorEventUpdateRelaunch:
					{
						// Log.
						_infoHandler(info);

						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_relaunching_tor", @"");
						
						break;
					}
						
					case SMTorEventUpdateDone:
					{
						// Log.
						_infoHandler(info);
						
						// Update UI.
						workingStatusField.stringValue = SMLocalizedString(@"update_status_update_done", @"");
						
						workingButton.title = SMLocalizedString(@"update_button_done", @"");
						workingButton.keyEquivalent = @"\r";
						
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
				workingProgress.hidden = YES;

				workingDownloadInfo.stringValue = [NSString stringWithFormat:SMLocalizedString(@"update_error_fmt", @""), [info renderMessage]];
				workingDownloadInfo.hidden = NO;

				workingStatusField.stringValue = SMLocalizedString(@"update_status_error", @"");
				workingButton.title = SMLocalizedString(@"update_button_close", @"");
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
	_selfRetain = nil;
}

- (IBAction)doInstallUpdate:(id)sender
{
	// Compute new rect.
	NSSize oldSize = availableView.frame.size;
	NSSize newSize = workingView.frame.size;
	
	NSRect frame = self.window.frame;
	NSRect rect;

	rect.size = NSMakeSize(frame.size.width + (newSize.width - oldSize.width), frame.size.height + (newSize.height - oldSize.height));
	rect.origin = NSMakePoint(frame.origin.x + (frame.size.width - rect.size.width) / 2.0, frame.origin.y + (frame.size.height - rect.size.height) / 2.0);

	availableView.alphaValue = 1.0;
	workingView.alphaValue = 0.0;
	
	[self.window.contentView addSubview:workingView];

	[NSAnimationContext runAnimationGroup:^(NSAnimationContext *context) {
		context.duration = 0.1;
		availableView.animator.alphaValue = 0.0;
		workingView.animator.alphaValue = 1.0;
		[self.window.animator setFrame:rect display:YES];
	} completionHandler:^{
		[availableView removeFromSuperview];
		[self _doUpdate];
	}];
}

- (IBAction)doWorkingButton:(id)sender
{
	if (!_updateDone && _currentCancelBlock)
		_currentCancelBlock();
	
	_currentCancelBlock = nil;
	
	[self close];
	_selfRetain = nil;
}

@end


NS_ASSUME_NONNULL_END
