/*
 *  SMTorManager.h
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

#import <Foundation/Foundation.h>

#import <SMTor/SMTorInformations.h>


NS_ASSUME_NONNULL_BEGIN


/*
** Forward
*/
#pragma mark - Forward

@class SMTorConfiguration;
@class SMInfo;



/*
** SMTorManager
*/
#pragma mark - SMTorManager

@interface SMTorManager : NSObject

// -- Instance --
- (id)initWithConfiguration:(SMTorConfiguration *)configuration;

// -- Life --
- (void)startWithInfoHandler:(nullable void (^)(SMInfo *info))handler;
- (void)stopWithCompletionHandler:(nullable dispatch_block_t)handler;

// -- Update --
- (dispatch_block_t)checkForUpdateWithInfoHandler:(void (^)(SMInfo *info))handler;
- (dispatch_block_t)updateWithInfoHandler:(void (^)(SMInfo *info))handler;

// -- Configuration --
- (BOOL)loadConfiguration:(SMTorConfiguration *)configuration infoHandler:(nullable void (^)(SMInfo *info))hander;
- (SMTorConfiguration *)configuration;

// -- Events --
@property (strong, atomic, nullable) void (^logHandler)(SMTorLogKind kind, NSString *log);

@end


NS_ASSUME_NONNULL_END
