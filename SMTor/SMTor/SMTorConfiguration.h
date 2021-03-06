/*
 *  SMTorConfiguration.h
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

#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorConfiguration
*/
#pragma mark - SMTorConfiguration

@interface SMTorConfiguration : NSObject <NSCopying>

// -- Socks --
@property (nonatomic)			NSString	*socksHost;
@property (nonatomic)			uint16_t	socksPort;

// -- Hidden Service --
@property (nonatomic)			BOOL		hiddenService;

@property (nullable, nonatomic) NSString	*hiddenServicePrivateKey;

@property (nonatomic)			uint16_t	hiddenServiceRemotePort;

@property (nonatomic)			NSString	*hiddenServiceLocalHost;
@property (nonatomic)			uint16_t	hiddenServiceLocalPort;

// -- Path --
@property (nonatomic)			NSString	*binaryPath;
@property (nonatomic)			NSString	*dataPath;


// -- Tools --
@property (readonly, getter=isValid) BOOL valid;

- (BOOL)differFromConfiguration:(SMTorConfiguration *)configuration;

@end


NS_ASSUME_NONNULL_END
