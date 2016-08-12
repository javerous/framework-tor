/*
 *  SMTorInformations.h
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


#pragma once


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
	SMTorWarningStartCorruptedRetry,
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
