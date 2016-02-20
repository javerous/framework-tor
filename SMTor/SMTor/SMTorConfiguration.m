/*
 *  SMTorConfiguration.m
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

#import "SMTorConfiguration.h"


NS_ASSUME_NONNULL_BEGIN


/*
** SMTorConfiguration
*/
#pragma mark - SMTorConfiguration

@implementation SMTorConfiguration

- (id)copyWithZone:(nullable NSZone *)zone
{
	SMTorConfiguration *copy = [[SMTorConfiguration allocWithZone:zone] init];
	
	// Socks.
	copy.socksHost = [_socksHost copy];
	copy.socksPort = _socksPort;

	// Hidden service.
	copy.hiddenService = _hiddenService;
	copy.hiddenServiceRemotePort = _hiddenServiceRemotePort;
	copy.hiddenServiceLocalHost = [_hiddenServiceLocalHost copy];
	copy.hiddenServiceLocalPort = _hiddenServiceLocalPort;

	// Path.
	copy.binaryPath = [_binaryPath copy];
	copy.identityPath = [_identityPath copy];
	copy.dataPath = [_dataPath copy];

	return copy;
}

- (BOOL)differFromConfiguration:(SMTorConfiguration *)configuration
{
	BOOL differ = NO;
	
	// Socks.
	differ = differ || ([_socksHost isEqualToString:configuration.socksHost] == NO);
	differ = differ || (_socksPort != configuration.socksPort);

	// Hidden service.
	differ = differ || (_hiddenService != configuration.hiddenService);
	
	if (!_hiddenService && configuration.hiddenService)
	{
		differ = differ || (_hiddenServiceRemotePort != configuration.hiddenServiceRemotePort);
		differ = differ || ([_hiddenServiceLocalHost isEqualToString:configuration.hiddenServiceLocalHost] == NO);
		differ = differ || (_hiddenServiceLocalPort != configuration.hiddenServiceLocalPort);
		
		differ = differ || ([_identityPath isEqualToString:configuration.identityPath] == NO);
	}
	
	// Path.
	differ = differ || ([_binaryPath isEqualToString:configuration.binaryPath] == NO);
	differ = differ || ([_dataPath isEqualToString:configuration.dataPath] == NO);
	
	return differ;
}

- (BOOL)isValid
{
	BOOL valid = YES;
	
	// Socks.
	valid = valid && (_socksHost != nil);
	valid = valid && (_socksPort >= 1);
	
	// Hidden service.
	if (_hiddenService)
	{
		valid = valid && (_hiddenServiceRemotePort > 1);
		valid = valid && (_hiddenServiceLocalHost != nil);
		valid = valid && (_hiddenServiceLocalPort > 1);
		
		valid = valid && (_identityPath != nil);
	}

	// Path.
	valid = valid && (_binaryPath != nil);
	valid = valid && (_dataPath != nil);
	
	return valid;
}

@end


NS_ASSUME_NONNULL_END
