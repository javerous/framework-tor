/*
 *  SMTorInformations.h
 *
 *  Copyright 2019 Avérous Julien-Pierre
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

typedef NS_ENUM(unsigned int, SMTorLogKind) {
	SMTorLogStandard,
	SMTorLogError
};

// == SMTorStart ==
typedef NS_ENUM(unsigned int, SMTorEventStart) {
	SMTorEventStartBootstrapping,		// context: @{ @"progress" : NSNumber, @"summary" : NSString }
	SMTorEventStartServiceID,			// context: NSString
	SMTorEventStartServicePrivateKey,	// context: NSString
	SMTorEventStartURLSession,			// context: NSURLSession
	SMTorEventStartDone,
};

typedef NS_ENUM(unsigned int, SMTorWarningStart) {
	SMTorWarningStartCanceled,
	SMTorWarningStartCorruptedRetry,
};

typedef NS_ENUM(unsigned int, SMTorErrorStart) {
	SMTorErrorStartAlreadyRunning,
	SMTorErrorStartConfiguration,
	SMTorErrorStartUnarchive,
	SMTorErrorStartSignature,
	SMTorErrorStartLaunch,
	SMTorErrorStartControlFile,
	SMTorErrorStartControlConnect,
	SMTorErrorStartControlAuthenticate,
	SMTorErrorStartControlHiddenService,
	SMTorErrorStartControlMonitor,
};


// == SMTorInfoCheckUpdateEvent ==
typedef NS_ENUM(unsigned int, SMTorEventCheckUpdate) {
	SMTorEventCheckUpdateAvailable,		// context: @{ @"old_version" : NSString, @"new_version" : NSString }
};

typedef NS_ENUM(unsigned int, SMTorErrorCheckUpdate) {
	SMTorErrorCheckUpdateTorNotRunning,
	SMTorErrorRetrieveRemoteInfo,		// info: SMInfo (<operation error>)
	SMTorErrorCheckUpdateLocalSignature,// info: SMInfo (<operation error>)
	
	SMTorErrorCheckUpdateNothingNew,
};


// == SMTorUpdate ==
typedef NS_ENUM(unsigned int, SMTorEventUpdate) {
	SMTorEventUpdateArchiveInfoRetrieving,
	SMTorEventUpdateArchiveSize,			// context: NSNumber (<archive size>)
	SMTorEventUpdateArchiveDownloading,		// context: NSNumber (<archive bytes downloaded>)
	SMTorEventUpdateArchiveStage,
	SMTorEventUpdateSignatureCheck,
	SMTorEventUpdateRelaunch,
	SMTorEventUpdateDone,
};

typedef NS_ENUM(unsigned int, SMTorErrorUpdate) {
	SMTorErrorUpdateTorNotRunning,
	SMTorErrorUpdateConfiguration,
	SMTorErrorUpdateInternal,
	SMTorErrorUpdateArchiveInfo,		// info: SMInfo (<operation error>)
	SMTorErrorUpdateArchiveDownload,	// context: NSError
	SMTorErrorUpdateArchiveStage,		// info: SMInfo (<operation error>)
	SMTorErrorUpdateRelaunch,			// info: SMInfo (<operation error>)
};


// == SMTorOperation ==
typedef NS_ENUM(unsigned int, SMTorEventOperation) {
	SMTorEventOperationInfo,			// context: NSDictionary
	SMTorEventOperationDone,
};

typedef NS_ENUM(unsigned int, SMTorErrorOperation) {
	SMTorErrorOperationConfiguration,
	SMTorErrorOperationIO,
	SMTorErrorOperationNetwork,		// context
	SMTorErrorOperationExtract,		// context: NSNumber (<tar result>)
	SMTorErrorOperationSignature,	// context: NSString (<path to the problematic file>)
	SMTorErrorOperationTor,			// context: NSNumber (<tor result>)
	
	SMTorErrorInternal
};
