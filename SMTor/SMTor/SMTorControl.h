/*
 *  SMTorControl.h
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


#import <Foundation/Foundation.h>
#import <SMFoundation/SMFoundation.h>


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorControl
*/
#pragma mark - SMTorControl

@interface SMTorControl : NSObject <SMSocketDelegate>

@property (strong, atomic) void (^serverEvent)(NSString *type, NSString *content);
@property (strong, atomic) void (^socketError)(SMInfo *info);

// -- Instance --
- (nullable instancetype)initWithIP:(NSString *)ip port:(uint16_t)port NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// -- Life --
- (void)stop;

// -- Commands --
- (void)sendAuthenticationCommandWithKeyHexa:(NSString *)keyHexa resultHandler:(void (^)(BOOL success))handler;
- (void)sendGetInfoCommandWithInfo:(NSString *)info resultHandler:(void (^)(BOOL success, NSString * _Nullable info))handler;
- (void)sendSetEventsCommandWithEvents:(NSString *)events resultHandler:(void (^)(BOOL success))handler;
- (void)sendAddOnionCommandWithPrivateKey:(nullable NSString *)privateKey port:(NSString *)servicePort resultHandler:(void (^)(BOOL success, NSString * _Nullable serviceID, NSString * _Nullable privateKey))handler;

// -- Helpers --
+ (nullable NSDictionary *)parseNoticeBootstrap:(NSString *)line;

@end


NS_ASSUME_NONNULL_END
