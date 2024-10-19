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

package com.aniable.anibl.oauth2.userinfo;

import com.aniable.anibl.oauth2.OAuth2Provider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class OAuth2UserInfoFactory {

	public static OAuth2UserInfo getOAuth2UserInfo(OAuth2User oAuth2User, OAuth2UserRequest oAuth2UserRequest) {
		var oAuth2Provider = OAuth2Provider.fromClientRegistration(oAuth2UserRequest.getClientRegistration());
		switch (oAuth2Provider) {
			case GITHUB -> {
				return new GitHubOAuth2UserInfo(oAuth2User.getAttributes());
			}
			case null, default -> throw new RuntimeException(
				"Unsupported OAuth2 provider: " + oAuth2UserRequest.getClientRegistration().getRegistrationId());
		}
	}
}
