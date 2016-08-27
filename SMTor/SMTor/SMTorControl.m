/*
 *  SMTorControl.m
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


#import "SMTorControl.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Types
*/
#pragma mark - Types

typedef void (^SMTorControlLineHandler)(NSNumber *code, NSString * _Nullable line, BOOL *finished);


/*
** SMTorControl
*/
#pragma mark - SMTorControl

@implementation SMTorControl
{
	dispatch_queue_t _localQueue;
	
	SMSocket *_socket;
	
	NSRegularExpression *_regexpEvent;
	
	NSMutableArray			*_lineHandlers;
	SMTorControlLineHandler _currentLineHandler;
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
		
		SMDebugLog(@"Connected to Tor Control (%@:%d)", ip, port);
		
		_socket.delegate = self;
		
		[_socket setGlobalOperation:SMSocketOperationLine size:0 tag:0];
		
		// Containers.
		_lineHandlers = [[NSMutableArray alloc] init];
		
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
		BOOL finished = NO;
		
		if (_currentLineHandler)
			_currentLineHandler(@(551), nil, &finished);
		
		for (SMTorControlLineHandler handler in _lineHandlers)
			handler(@(551), nil, &finished);
		
		[_lineHandlers removeAllObjects];
		_currentLineHandler = nil;
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
		
		[self _addHandler:^(NSNumber * _Nonnull code, NSString * _Nullable line, BOOL * _Nonnull finished) {
			*finished = YES;
			handler(code.integerValue == 250);
		}];
		
		[_socket sendBytes:command.bytes size:command.length copy:YES];
	});
}

- (void)sendGetInfoCommandWithInfo:(NSString *)info resultHandler:(void (^)(BOOL success, NSString * _Nullable info))handler
{
	NSAssert(info, @"info is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{
		
		NSData *command = [[NSString stringWithFormat:@"GETINFO %@\n", info] dataUsingEncoding:NSASCIIStringEncoding];
		
		[self _addHandler:^(NSNumber * _Nonnull code, NSString * _Nullable line, BOOL * _Nonnull finished) {
			
			*finished = YES;
			
			// Check code.
			if (code.integerValue != 250)
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
		
		[_socket sendBytes:command.bytes size:command.length copy:YES];
	});
}

- (void)sendSetEventsCommandWithEvents:(NSString *)events resultHandler:(void (^)(BOOL success))handler
{
	NSAssert(events, @"events is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{
		
		NSData *command = [[NSString stringWithFormat:@"SETEVENTS %@\n", events] dataUsingEncoding:NSASCIIStringEncoding];
		
		[self _addHandler:^(NSNumber * _Nonnull code, NSString * _Nullable line, BOOL * _Nonnull finished) {
			*finished = YES;
			handler(code.integerValue == 250);
		}];
		
		[_socket sendBytes:command.bytes size:command.length copy:YES];
	});
}

- (void)sendAddOnionCommandWithPrivateKey:(nullable NSString *)privateKey port:(NSString *)servicePort resultHandler:(void (^)(BOOL success, NSString * _Nullable serviceID, NSString * _Nullable privateKey))handler
{
	NSAssert(servicePort, @"servicePort is nil");
	NSAssert(handler, @"handler is nil");
	
	dispatch_async(_localQueue, ^{
		
		// Forge command.
		NSData *command;
		
		if (privateKey)
			command = [[NSString stringWithFormat:@"ADD_ONION %@ Flags=Detach Port=%@\n", privateKey, servicePort] dataUsingEncoding:NSASCIIStringEncoding];
		else
			command = [[NSString stringWithFormat:@"ADD_ONION NEW:BEST Flags=Detach Port=%@\n", servicePort] dataUsingEncoding:NSASCIIStringEncoding];
		
		// Handle command result.
		__block NSString *resultServiceID = nil;
		__block NSString *resultPrivateKey = nil;

		[self _addHandler:^(NSNumber * _Nonnull code, NSString * _Nullable line, BOOL * _Nonnull finished) {
			
			if (code.integerValue == 250)
			{
				if ([line caseInsensitiveCompare:@"OK"] == NSOrderedSame)
				{
					*finished = YES;
					
					if ((privateKey == nil && resultPrivateKey == nil) || (privateKey != nil && resultPrivateKey != nil))
						handler(NO, nil, nil);
					else
						handler(YES, resultServiceID, resultPrivateKey);
				}
				else
				{
					NSString *serviceIDToken = @"-ServiceID=";
					NSString *privateKeyToken = @"-PrivateKey=";

					if ([line hasPrefix:serviceIDToken] && line.length > serviceIDToken.length)
						resultServiceID = [line substringFromIndex:serviceIDToken.length];
					else if ([line hasPrefix:privateKeyToken] && line.length > privateKeyToken.length)
						resultPrivateKey = [line substringFromIndex:privateKeyToken.length];
					
					*finished = NO;
				}
			}
			else
			{
				*finished = YES;
				handler(NO, nil, nil);
			}
		}];
		
		// Send command.
		[_socket sendBytes:command.bytes size:command.length copy:YES];
	});
}




/*
 ** SMTorControl - Helpers
 */
#pragma mark - SMTorControl - Helpers

+ (nullable NSDictionary *)parseNoticeBootstrap:(NSString *)line
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
	
	NSTextCheckingResult *match = matches.firstObject;
	
	if (match.numberOfRanges != 4)
		return nil;
	
	// Extract.
	NSString *progress = [line substringWithRange:[match rangeAtIndex:1]];
	NSString *tag = [line substringWithRange:[match rangeAtIndex:2]];
	NSString *summary = [line substringWithRange:[match rangeAtIndex:3]];
	
	return @{ @"progress" : @(progress.integerValue), @"tag" : tag, @"summary" : [summary stringByReplacingOccurrencesOfString:@"\\\"" withString:@"\""] };
}


- (void)_addHandler:(SMTorControlLineHandler)handler
{
	// > localQueue <
	
	[_lineHandlers addObject:handler];
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
			NSInteger	codeValue = code.integerValue;
			
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
				
				NSTextCheckingResult *match = matches.firstObject;
				
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
				if (_currentLineHandler == nil)
				{
					if (_lineHandlers.count == 0)
						continue;
					
					_currentLineHandler = _lineHandlers[0];
					
					[_lineHandlers removeObjectAtIndex:0];
				}
				
				// Give content.
				BOOL finished = NO;
				
				_currentLineHandler(@(codeValue), info, &finished);
				
				if (finished)
					_currentLineHandler = nil;
			}
		}
	});
}

- (void)socket:(SMSocket *)socket error:(SMInfo *)error
{
	// Finish handlers.
	dispatch_async(_localQueue, ^{
		
		BOOL finished = NO;

		if (_currentLineHandler)
			_currentLineHandler(@(551), nil, &finished);
		
		for (SMTorControlLineHandler handler in _lineHandlers)
			handler(@(551), nil, &finished);
		
		[_lineHandlers removeAllObjects];
		_currentLineHandler = nil;
	});
	
	// Notify error.
	void (^socketError)(SMInfo *info) = self.socketError;
	
	if (!socketError)
		return;
	
	socketError(error);
}

@end


NS_ASSUME_NONNULL_END
