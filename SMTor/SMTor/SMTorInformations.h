//
//  SMTorInformations.h
//  SMTor
//
//  Created by Julien-Pierre Avérous on 10/08/2016.
//  Copyright © 2016 Julien-Pierre Avérous. All rights reserved.
//

#ifndef SMTorInformations_h
# define SMTorInformations_h


/*
** Domains
*/
#pragma mark Domains

#define SMTorInfoStartDomain		@"SMTorInfoStartDomain"

#define SMTorInfoCheckUpdateDomain	@"SMTorInfoCheckUpdateDomain"
#define SMTorInfoUpdateDomain		@"SMTorInfoUpdateDomain"

#define SMTorInfoOperationDomain	@"SMTorInfoOperationDomain"


/*
** Types
*/
#pragma mark - Types

typedef enum
{
	SMTorLogStandard,
	SMTorLogError
} SMTorLogKind;

// == SMTorStart ==
typedef enum
{
	SMTorEventStartBootstrapping,		// context: @{ @"progress" : NSNumber, @"summary" : NSString }
	SMTorEventStartServiceID,			// context: NSString
	SMTorEventStartServicePrivateKey,	// context: NSString
	SMTorEventStartURLSession,			// context: NSURLSession
	SMTorEventStartDone,
} SMTorEventStart;

typedef enum
{
	SMTorWarningStartCanceled,
} SMTorWarningStart;

typedef enum
{
	SMTorErrorStartAlreadyRunning,
	SMTorErrorStartConfiguration,
	SMTorErrorStartUnarchive,
	SMTorErrorStartSignature,
	SMTorErrorStartLaunch,
	SMTorErrorStartControlConnect,
	SMTorErrorStartControlAuthenticate,
	SMTorErrorStartControlHiddenService,
	SMTorErrorStartControlMonitor,
} SMTorErrorStart;


// == SMTorInfoCheckUpdateEvent ==
typedef enum
{
	SMTorEventCheckUpdateAvailable,		// context: @{ @"old_version" : NSString, @"new_version" : NSString }
} SMTorEventCheckUpdate;

typedef enum
{
	SMTorErrorCheckUpdateTorNotRunning,
	SMTorErrorRetrieveRemoteInfo,		// info: SMInfo (<operation error>)
	SMTorErrorCheckUpdateLocalSignature,// info: SMInfo (<operation error>)
	
	SMTorErrorCheckUpdateNothingNew,
} SMTorErrorCheckUpdate;


// == SMTorUpdate ==
typedef enum
{
	SMTorEventUpdateArchiveInfoRetrieving,
	SMTorEventUpdateArchiveSize,			// context: NSNumber (<archive size>)
	SMTorEventUpdateArchiveDownloading,		// context: NSNumber (<archive bytes downloaded>)
	SMTorEventUpdateArchiveStage,
	SMTorEventUpdateSignatureCheck,
	SMTorEventUpdateRelaunch,
	SMTorEventUpdateDone,
} SMTorEventUpdate;

typedef enum
{
	SMTorErrorUpdateTorNotRunning,
	SMTorErrorUpdateConfiguration,
	SMTorErrorUpdateInternal,
	SMTorErrorUpdateArchiveInfo,		// info: SMInfo (<operation error>)
	SMTorErrorUpdateArchiveDownload,	// context: NSError
	SMTorErrorUpdateArchiveStage,		// info: SMInfo (<operation error>)
	SMTorErrorUpdateRelaunch,			// info: SMInfo (<operation error>)
} SMTorErrorUpdate;


// == SMTorOperation ==
typedef enum
{
	SMTorEventOperationInfo,			// context: NSDictionary
	SMTorEventOperationDone,
} SMTorEventOperation;

typedef enum
{
	SMTorErrorOperationConfiguration,
	SMTorErrorOperationIO,
	SMTorErrorOperationNetwork,		// context
	SMTorErrorOperationExtract,		// context: NSNumber (<tar result>)
	SMTorErrorOperationSignature,	// context: NSString (<path to the problematic file>)
	SMTorErrorOperationTor,			// context: NSNumber (<tor result>)
	
	SMTorErrorInternal
} SMTorErrorOperation;

#endif /* SMTorInformations_h */
