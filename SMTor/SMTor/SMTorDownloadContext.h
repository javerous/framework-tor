//
//  SMTorDownloadContext.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


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


NS_ASSUME_NONNULL_END
