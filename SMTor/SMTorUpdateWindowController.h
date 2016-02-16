/*
 *  SMTorUpdateWindowController.h
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

#import <Cocoa/Cocoa.h>


NS_ASSUME_NONNULL_BEGIN


/*
** Forward
*/
#pragma mark - Forward

@class SMTorManager;



/*
** SMTorUpdateWindowController
*/
#pragma mark - SMTorUpdateWindowController

@interface SMTorUpdateWindowController : NSWindowController

// -- Instance --
+ (instancetype)sharedController;

// -- Tools --
- (void)handleUpdateFromVersion:(NSString *)oldVersion toVersion:(NSString *)newVersion torManager:(SMTorManager *)torManager logHandler:(nullable void (^)(SMInfo *info))logHandler;

@end


NS_ASSUME_NONNULL_END
