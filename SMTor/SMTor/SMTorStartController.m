/*
 *  SMTorStartController.m
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

#import "SMTorStartController.h"

#import "SMTorManager.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorStartWindowController - Interface
*/
#pragma mark - SMTorStartWindowController - Interface

@interface SMTorStartWindowController : NSWindowController

- (instancetype)initWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler NS_DESIGNATED_INITIALIZER;

- (nullable instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;
- (instancetype)initWithWindow:(nullable NSWindow *)window NS_UNAVAILABLE;

- (void)_startModal;

@end



/*
** SMTorStartController
*/
#pragma mark - SMTorStartController

@implementation SMTorStartController

+ (void)startWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler
{
	CFRunLoopRef runLoop = CFRunLoopGetMain();

	CFRunLoopPerformBlock(runLoop, kCFRunLoopCommonModes, ^{

		SMTorStartWindowController *ctrl = [[SMTorStartWindowController alloc] initWithTorManager:torManager infoHandler:handler];

		[ctrl _startModal];
	});
	
	CFRunLoopWakeUp(runLoop);
}

@end



/*
** SMTorStartWindowController
*/
#pragma mark - SMTorStartWindowController

@implementation SMTorStartWindowController
{
	IBOutlet NSButton				*cancelButton;
	IBOutlet NSTextField			*summaryField;
	IBOutlet NSProgressIndicator	*progressIndicator;
	
	SMTorStartWindowController *_selfRetain;
	
	SMTorManager *_torManager;
	
	void (^_handler)(SMInfo *info);
	
	BOOL	_isBootstrapping;
	
	SMInfo	*_error;
	
	NSModalSession _modalSession;
}


/*
** SMTorStartWindowController - Instance
*/
#pragma mark - SMTorStartWindowController - Instance

- (instancetype)initWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler
{
	self = [super initWithWindow:nil];
	
	if (self)
	{
		NSAssert(torManager, @"torManager is nil");
		NSAssert(handler, @"handler is nil");

		_torManager = torManager;
		_handler = handler;
		
		// Self retain.
		_selfRetain = self;
	}
	
	return self;
}



/*
** SMTorStartWindowController - NSWindowController
*/
#pragma mark - SMTorStartWindowController - NSWindowController

- (nullable NSString *)windowNibName
{
	return @"StartWindow";
}

- (id)owner
{
	return self;
}



/*
** SMTorStartWindowController - IBAction
*/
#pragma mark - SMTorStartWindowController - IBAction

- (IBAction)doCancel:(id)sender
{
	if (_error)
	{
		_handler(_error);
		
		[self _closeWindow];
	}
	else
	{
		cancelButton.enabled = NO;
		
		if (_isBootstrapping)
		{
			summaryField.hidden = YES;
			[progressIndicator setIndeterminate:YES];
		}
		
		[_torManager stopWithCompletionHandler:^{
			dispatch_async(dispatch_get_main_queue(), ^{
				[self _closeWindow];
			});
		}];
	}
}



/*
** SMTorStartWindowController - Helpers
*/
#pragma mark - SMTorStartWindowController - Helpers

- (void)_startModal
{
	// Configure window behavior.
	self.window.preventsApplicationTerminationWhenModal = YES;
	self.window.animationBehavior = NSWindowAnimationBehaviorDocumentWindow;
	
	// Create modal session and start it.
	_modalSession = [[NSApplication sharedApplication] beginModalSessionForWindow:self.window];
	
	[[NSApplication sharedApplication] runModalSession:_modalSession];
	
	// Start tor manager.
	[progressIndicator startAnimation:nil];
	
	[_torManager startWithInfoHandler:^(SMInfo *info) {
		
		dispatch_async(dispatch_get_main_queue(), ^{
			
			if ([info.domain isEqualToString:SMTorInfoStartDomain] == NO)
				return;
			
			// Dispatch info.
			switch (info.kind)
			{
				case SMInfoInfo:
				{
					// > Forward info.
					_handler(info);
					
					// > Handle code.
					switch ((SMTorEventStart)info.code)
					{
						case SMTorEventStartBootstrapping:
						{
							NSDictionary	*context = info.context;
							NSString		*summary = context[@"summary"];
							NSNumber		*progress = context[@"progress"];
							
							if (!_isBootstrapping)
							{
								progressIndicator.indeterminate = NO;
								summaryField.hidden = NO;
								
								_isBootstrapping = YES;
							}
							
							progressIndicator.doubleValue = progress.doubleValue;
							summaryField.stringValue = summary;
							
							if (_isBootstrapping && progress.doubleValue >= 100)
							{
								progressIndicator.indeterminate = YES;
								summaryField.hidden = YES;
								
								_isBootstrapping = NO;
							}
							
							break;
						}
							
						case SMTorEventStartDone:
						{
							[self _closeWindow];
							break;
						}
							
						default:
							break;
					}
					
					break;
				}
					
				case SMInfoWarning:
				{
					// > Handle code.
					switch ((SMTorWarningStart)info.code)
					{
						case SMTorWarningStartCanceled:
						{
							[self _closeWindow];
							break;
						}
							
						case SMTorWarningStartCorruptedRetry:
							break;
					}
					
					// > Forward info.
					_handler(info);
					
					break;
				}
					
				case SMInfoError:
				{
					summaryField.textColor = [NSColor redColor];
					summaryField.stringValue = [NSString stringWithFormat:@"Code %d - %@", info.code, [info renderMessage]];
					summaryField.hidden = NO;
					
					cancelButton.title = SMLocalizedString(@"tor_button_close", @"");
					
					_error = info;
					
					break;
				}
			}
		});
	}];
}

- (void)_closeWindow
{
	// > main queue <
	
	if (!_modalSession)
		return;
	
	[self close];
	
	[[NSApplication sharedApplication] endModalSession:_modalSession];
	
	_modalSession = NULL;
	_selfRetain = nil;
}


@end


NS_ASSUME_NONNULL_END
