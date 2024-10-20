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

package com.aniable.anibl.jwt;

import com.aniable.anibl.user.User;
import com.aniable.anibl.util.DateTimeUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

	private SecretKey getSecretKey() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode("DZhCI4P6bysu+sXYN5yL25QpEq1NqvUYJDvwKxaPH+o="));
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
	}

	private <T> T extractClaim(String token, Function<Claims, T> resolver) {
		var claims = extractAllClaims(token);
		return resolver.apply(claims);
	}

	public String extractSubject(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public String build(User user) {
		var zonedNow = DateTimeUtils.now();
		var iat = Date.from(zonedNow.toInstant());
		var exp = Date.from(zonedNow.plusYears(100)
									.toInstant()); // TODO 2024-10-19, 14:57 The expiration will be changed to be shorter once refresh tokens are implemented.

		return Jwts.builder()
				   .issuedAt(iat)
				   .notBefore(iat)
				   .expiration(exp)
				   .subject(user.getId().toString())
				   .signWith(getSecretKey())
				   .compact();
	}
}
