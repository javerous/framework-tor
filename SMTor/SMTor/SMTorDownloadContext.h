/*
 *  SMTorDownloadContext.h
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


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorDownloadContext
*/
#pragma mark - SMTorDownloadContext

@interface SMTorDownloadContext : NSObject

// -- Instance --
- (nullable instancetype)initWithPath:(NSString *)path NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// -- Methods --
- (void)handleData:(NSData *)data;
- (void)handleComplete:(NSError *)error;

@property (nonatomic, readonly, copy) NSData *sha256;

- (void)close;

// -- Properties --
@property (strong, nonatomic) void (^updateHandler) (SMTorDownloadContext *context, NSUInteger bytesDownloaded, BOOL complete, NSError * _Nullable error);

@end


NS_ASSUME_NONNULL_END
