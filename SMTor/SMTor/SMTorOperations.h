//
//  SMTorOperations.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "SMTorInformations.h"


NS_ASSUME_NONNULL_BEGIN


/*
** Forward
*/
#pragma mark - Forward

@class SMInfo;
@class SMTorConfiguration;


/*
** SMTorOperations
*/
#pragma mark - SMTorOperations

@interface SMTorOperations : NSObject

+ (dispatch_block_t)operationRetrieveRemoteInfoWithURLSession:(NSURLSession *)urlSession completionHandler:(void (^)(SMInfo *info))handler;
+ (void)operationStageArchiveFile:(NSURL *)fileURL toTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler;
+ (void)operationCheckSignatureWithTorBinariesPath:(NSString *)torBinPath completionHandler:(nullable void (^)(SMInfo *info))handler;
+ (void)operationLaunchTorWithConfiguration:(SMTorConfiguration *)configuration logHandler:(nullable void (^)(SMTorLogKind kind, NSString *log))logHandler completionHandler:(void (^)(SMInfo *info, NSTask * _Nullable task, NSString * _Nullable ctrlKeyHexa))handler;

@end

NS_ASSUME_NONNULL_END
