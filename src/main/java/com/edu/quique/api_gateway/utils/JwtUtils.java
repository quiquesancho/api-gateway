package com.edu.quique.api_gateway.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import static com.edu.quique.api_gateway.utils.AppConstants.TOKEN_BEARER_PREFIX;

@Service
public class JwtUtils {

  @Value("$privateKey")
  private String privateKey;

  public Claims getJwtClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSigningKey(privateKey))
        .build()
        .parseClaimsJws(token.replace(TOKEN_BEARER_PREFIX, StringUtils.EMPTY))
        .getBody();
  }

  public boolean isExpired(String token) {
    try {
      return getJwtClaims(token).getExpiration().before(new Date());
    } catch (Exception e) {
      return true;
    }
  }

  public String extractSubject(String token) {
    try {
      return getJwtClaims(token).getSubject();
    } catch (Exception e) {
      return null;
    }
  }

  private Key getSigningKey(String secret) {
    byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
