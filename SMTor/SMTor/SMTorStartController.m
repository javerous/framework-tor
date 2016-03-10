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

@import SMFoundation;

#import "SMTorStartController.h"

#import "SMTorManager.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorStartWindowController - Interface
*/
#pragma mark - SMTorStartWindowController - Interface

@interface SMTorStartWindowController : NSWindowController

- (instancetype)initWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler;

@end



/*
** SMTorStartController
*/
#pragma mark - SMTorStartController

@implementation SMTorStartController

+ (void)startWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler
{
	dispatch_async(dispatch_get_main_queue(), ^{
		
		SMTorStartWindowController *ctrl = [[SMTorStartWindowController alloc] initWithTorManager:torManager infoHandler:handler];
		
		[ctrl showWindow:nil];
	});
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
	
	SMTorManager *_torManager;
	
	void (^_handler)(SMInfo *info);
	
	BOOL	_isBootstrapping;
	BOOL	_isError;
}


/*
** SMTorStartWindowController - Instance
*/
#pragma mark - SMTorStartWindowController - Instance

- (instancetype)initWithTorManager:(SMTorManager *)torManager infoHandler:(void (^)(SMInfo *info))handler
{
	self = [super initWithWindowNibName:@"StartWindow"];
	
	if (self)
	{
		if (!torManager || !handler)
			return nil;
		
		_torManager = torManager;
		_handler = handler;
	}
	
	return self;
}



/*
** SMTorStartWindowController - NSWindowController
*/
#pragma mark - SMTorStartWindowController - NSWindowController

- (void)windowDidLoad
{
	[super windowDidLoad];
	
	[self.window center];
	[progressIndicator startAnimation:nil];
	
	[_torManager startWithInfoHandler:^(SMInfo *info) {
		
		dispatch_async(dispatch_get_main_queue(), ^{

			if ([info.domain isEqualToString:SMTorManagerInfoStartDomain] == NO)
				return;
			
			// Forward info.
			_handler(info);

			// Handle info.
			switch (info.kind)
			{
				case SMInfoInfo:
				{
					switch ((SMTorManagerEventStart)info.code)
					{
						case SMTorManagerEventStartBootstrapping:
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
							
							progressIndicator.doubleValue = [progress doubleValue];
							summaryField.stringValue = summary;
							
							if (_isBootstrapping && [progress doubleValue] >= 100)
							{
								progressIndicator.indeterminate = YES;
								summaryField.hidden = YES;
								
								_isBootstrapping = NO;
							}
							
							break;
						}
							
						case SMTorManagerEventStartDone:
						{
							[self close];
							break;
						}
							
						default:
							break;
					}
					
					break;
				}
					
				case SMInfoWarning:
				{
					switch ((SMTorManagerWarningStart)info.code)
					{
						case SMTorManagerWarningStartCanceled:
						{
							[self close];
							break;
						}
					}
					
					break;
				}
					
				case SMInfoError:
				{
					summaryField.textColor = [NSColor redColor];
					summaryField.stringValue = [info renderMessage];
					summaryField.hidden = NO;
					
					cancelButton.stringValue = SMLocalizedString(@"tor_button_close", @"");
					
					_isError = YES;
					
					break;
				}
			}
		});
	}];
}



/*
** SMTorStartWindowController - IBAction
*/
#pragma mark - SMTorStartWindowController - IBAction

- (IBAction)doCancel:(id)sender
{
	if (_isError)
	{
		[self close];
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
				[self close];
			});
		}];
	}
}

@end


NS_ASSUME_NONNULL_END
