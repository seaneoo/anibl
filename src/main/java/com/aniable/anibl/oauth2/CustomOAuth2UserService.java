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

import com.aniable.anibl.oauth2.userinfo.OAuth2UserInfo;
import com.aniable.anibl.oauth2.userinfo.OAuth2UserInfoFactory;
import com.aniable.anibl.user.User;
import com.aniable.anibl.user.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;

@Component
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

	final RestTemplate restTemplate = new RestTemplate();

	final UserRepository userRepository;

	public CustomOAuth2UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		var oAuth2User = super.loadUser(userRequest);
		var attributes = new HashMap<>(oAuth2User.getAttributes());

		var primaryEmail = getPrimaryEmail(userRequest);
		attributes.put("verified_primary_email", primaryEmail.email);

		var userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(userRequest, attributes);

		var foundUserOptional = userRepository.findByProviderAndProviderId(userInfo.getProvider(), userInfo.getId());
		return foundUserOptional.map(user -> updateOAuth2User(userInfo, user))
								.orElseGet(() -> createOAuth2User(userInfo));
	}

	private GitHubUserEmails getPrimaryEmail(OAuth2UserRequest userRequest) {
		var accessToken = userRequest.getAccessToken().getTokenValue();
		if (accessToken == null || accessToken.isBlank()) {
			throw new IllegalArgumentException("Invalid access token");
		}

		var url = "https://api.github.com/user/emails";

		var headers = new HttpHeaders();
		headers.setBearerAuth(accessToken);
		var httpEntity = new HttpEntity<>(headers);

		ResponseEntity<GitHubUserEmails[]> response;
		try {
			response = restTemplate.exchange(url, HttpMethod.GET, httpEntity, GitHubUserEmails[].class);
		} catch (Exception e) {
			throw new RuntimeException("Could not fetch user emails from GitHub", e);
		}

		if (!response.getStatusCode().is2xxSuccessful()) {
			throw new RuntimeException("Unexpected response status: " + response.getStatusCode());
		}

		var responseBody = response.getBody();
		if (responseBody == null || responseBody.length == 0) {
			throw new RuntimeException("Empty response body");
		}

		var primaryEmail = Arrays.stream(responseBody)
								 .filter(GitHubUserEmails::primary)
								 .findFirst()
								 .orElseThrow(() -> new RuntimeException("Primary email not found"));
		if (!primaryEmail.verified) throw new RuntimeException("Primary email is not verified");
		return primaryEmail;
	}

	private OAuth2User createOAuth2User(OAuth2UserInfo userInfo) {
		log.info("Attempting to create new user: {provider='{}', id='{}'}", userInfo.getProvider(), userInfo.getId());
		var user = User.builder()
					   .provider(userInfo.getProvider())
					   .providerId(userInfo.getId())
					   .name(userInfo.getName())
					   .email(userInfo.getEmail())
					   .build();
		try {
			var createdUser = userRepository.save(user);
			log.info("Created new user: {id='{}'}", createdUser.getId());
			return createdUser;
		} catch (Exception e) {
			log.warn("Failed to create new user: {provider='{}', id='{}'}", userInfo.getProvider(), userInfo.getId());
			return null;
		}
	}

	private OAuth2User updateOAuth2User(OAuth2UserInfo userInfo, User existingUser) {
		log.info("Attempting to update existing user: {id='{}'}", existingUser.getId());

		// Update properties
		existingUser.setName(userInfo.getName());
		existingUser.setEmail(userInfo.getEmail());

		try {
			var savedUser = userRepository.save(existingUser);
			log.info("Updated existing user: {id='{}'}", savedUser.getId());
			return savedUser;
		} catch (Exception e) {
			log.warn("Could not update existing user: {id='{}'}", existingUser.getId(), e);
			return null;
		}
	}

	record GitHubUserEmails(String email, boolean verified, boolean primary, String visibility) {

	}
}
