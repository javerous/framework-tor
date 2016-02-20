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

@import Foundation;


NS_ASSUME_NONNULL_BEGIN


/*
** Forward
*/
#pragma mark - Forward

@class SMTorConfiguration;



/*
** Globals
*/
#pragma mark - Globals

#define SMTorManagerInfoStartDomain			@"SMTorManagerInfoStartDomain"

#define SMTorManagerInfoCheckUpdateDomain	@"SMTorManagerInfoCheckUpdateDomain"
#define SMTorManagerInfoUpdateDomain		@"SMTorManagerInfoUpdateDomain"

#define SMTorManagerInfoOperationDomain		@"SMTorManagerInfoOperationDomain"




/*
** Forward
*/
#pragma mark - Forward

@class SMInfo;



/*
** Types
*/
#pragma mark - Types

typedef enum
{
	SMTorManagerLogStandard,
	SMTorManagerLogError
} SMTorManagerLogKind;

// == SMTorManagerStart ==
typedef enum
{
	SMTorManagerEventStartBootstrapping,	// context: @{ @"progress" : NSNumber, @"summary" : NSString }
	SMTorManagerEventStartHostname,			// context: NSString
	SMTorManagerEventStartURLSession,		// context: NSURLSession
	SMTorManagerEventStartDone,
} SMTorManagerEventStart;

typedef enum
{
	SMTorManagerWarningStartCanceled,
} SMTorManagerWarningStart;

typedef enum
{
	SMTorManagerErrorStartAlreadyRunning,
	SMTorManagerErrorStartConfiguration,
	SMTorManagerErrorStartUnarchive,
	SMTorManagerErrorStartSignature,
	SMTorManagerErrorStartLaunch,
	SMTorManagerErrorStartControlConnect,
	SMTorManagerErrorStartControlAuthenticate,
	SMTorManagerErrorStartControlMonitor,
} SMTorManagerErrorStart;


// == SMTorManagerInfoCheckUpdateEvent ==
typedef enum
{
	SMTorManagerEventCheckUpdateAvailable,		// context: @{ @"old_version" : NSString, @"new_version" : NSString }
} SMTorManagerEventCheckUpdate;

typedef enum
{
	SMTorManagerErrorCheckUpdateTorNotRunning,
	SMTorManagerErrorRetrieveRemoteInfo,		// info: SMInfo (<operation error>)
	SMTorManagerErrorCheckUpdateLocalSignature,	// info: SMInfo (<operation error>)

	SMTorManagerErrorCheckUpdateNothingNew,
} SMTorManagerErrorCheckUpdate;


// == SMTorManagerUpdate ==
typedef enum
{
	SMTorManagerEventUpdateArchiveInfoRetrieving,
	SMTorManagerEventUpdateArchiveSize,			// context: NSNumber (<archive size>)
	SMTorManagerEventUpdateArchiveDownloading,	// context: NSNumber (<archive bytes downloaded>)
	SMTorManagerEventUpdateArchiveStage,
	SMTorManagerEventUpdateSignatureCheck,
	SMTorManagerEventUpdateRelaunch,
	SMTorManagerEventUpdateDone,
} SMTorManagerEventUpdate;

typedef enum
{
	SMTorManagerErrorUpdateTorNotRunning,
	SMTorManagerErrorUpdateConfiguration,
	SMTorManagerErrorUpdateInternal,
	SMTorManagerErrorUpdateArchiveInfo,		// info: SMInfo (<operation error>)
	SMTorManagerErrorUpdateArchiveDownload,	// context: NSError
	SMTorManagerErrorUpdateArchiveStage,	// info: SMInfo (<operation error>)
	SMTorManagerErrorUpdateRelaunch,		// info: SMInfo (<operation error>)
} SMTorManagerErrorUpdate;


// == SMTorManagerOperation ==
typedef enum
{
	SMTorManagerEventOperationInfo,			// context: NSDictionary
	SMTorManagerEventOperationDone,
} SMTorManagerEventOperation;

typedef enum
{
	SMTorManagerErrorOperationConfiguration,
	SMTorManagerErrorOperationIO,
	SMTorManagerErrorOperationNetwork,		// context
	SMTorManagerErrorOperationExtract,		// context: NSNumber (<tar result>)
	SMTorManagerErrorOperationSignature,	// context: NSString (<path to the problematic file>)
	SMTorManagerErrorOperationTor,			// context: NSNumber (<tor result>)

	SMTorManagerErrorInternal
} SMTorManagerErrorOperation;



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

// -- Events --
@property (strong, atomic, nullable) void (^logHandler)(SMTorManagerLogKind kind, NSString *log);

@end


NS_ASSUME_NONNULL_END
