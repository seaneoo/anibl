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

import java.util.HashMap;

public class GitHubOAuth2UserInfo extends OAuth2UserInfo {

	public GitHubOAuth2UserInfo(HashMap<String, Object> attributes) {
		super(attributes);
	}

	@Override
	public OAuth2Provider getProvider() {
		return OAuth2Provider.GITHUB;
	}

	@Override
	public String getId() {
		return getAttributes().get("id").toString();
	}

	@Override
	public String getName() {
		return getAttributes().get("login").toString();
	}

	@Override
	public String getEmail() {
		return getAttributes().get("verified_primary_email").toString();
	}
}
