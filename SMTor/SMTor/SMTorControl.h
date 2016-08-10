//
//  SMTorControl.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

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
- (nullable instancetype)initWithIP:(NSString *)ip port:(uint16_t)port;

// -- Life --
- (void)stop;

// -- Commands --
- (void)sendAuthenticationCommandWithKeyHexa:(NSString *)keyHexa resultHandler:(void (^)(BOOL success))handler;
- (void)sendGetInfoCommandWithInfo:(NSString *)info resultHandler:(void (^)(BOOL success, NSString * _Nullable info))handler;
- (void)sendSetEventsCommandWithEvents:(NSString *)events resultHandler:(void (^)(BOOL success))handler;
- (void)sendAddOnionCommandWithPrivateKey:(nullable NSString *)privateKey port:(NSString *)servicePort resultHandler:(void (^)(BOOL success, NSString * _Nullable serviceID, NSString * _Nullable privateKey))handler;

// -- Helpers --
+ (NSDictionary *)parseNoticeBootstrap:(NSString *)line;

@end


NS_ASSUME_NONNULL_END
