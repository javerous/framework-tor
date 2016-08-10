//
//  SMTorTask.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <SMFoundation/SMFoundation.h>

#import "SMTorInformations.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Forward
*/
#pragma mark - Forward

@class SMTorConfiguration;
@class SMTorDownloadContext;



/*
** SMTorTask
*/
#pragma mark - SMTorTask

@interface SMTorTask : NSObject <NSURLSessionDelegate>

@property (strong, atomic) void (^logHandler)(SMTorLogKind kind, NSString *log);

// -- Life --
- (void)startWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info))handler;
- (void)stopWithCompletionHandler:(nullable dispatch_block_t)handler;

// -- Download Context --
- (void)addDownloadContext:(SMTorDownloadContext *)context forKey:(id <NSCopying>)key;
- (void)removeDownloadContextForKey:(id)key;

@end

NS_ASSUME_NONNULL_END
