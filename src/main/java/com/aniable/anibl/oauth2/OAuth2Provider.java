/*
 * Copyright (C) 2024 Sean O'Connor
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package com.aniable.anibl.oauth2;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

public enum OAuth2Provider {
	GITHUB;

	public static OAuth2Provider fromClientRegistration(ClientRegistration clientRegistration) {
		try {
			return valueOf(clientRegistration.getRegistrationId().toUpperCase());
		} catch (Exception e) {
			return null;
		}
	}
}
