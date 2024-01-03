package com.fitnessdiary.service.auth.impl;

import com.fitnessdiary.service.auth.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

/**
 * Implementation of the JWTService interface providing methods for handling JSON Web Tokens (JWTs) in a Spring Security context.
 */
@Service
public class JWTServiceImpl implements JWTService {

    /**
     * Generates a refresh token with optional extra claims for a given user.
     *
     * @param extraClaims Additional claims to include in the refresh token payload.
     * @param userDetails UserDetails object representing the user for whom the token is generated.
     * @return A string representing the generated refresh token.
     */
    public String generateRefreshToken(Map<String,Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenLifespan))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generates an access token for a given user.
     *
     * @param userDetails UserDetails object representing the user for whom the token is generated.
     * @return A string representing the generated access token.
     */
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + tokenLifespan))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Checks whether a given JWT is valid for a specific user.
     *
     * @param token       The JWT to be validated.
     * @param userDetails UserDetails object representing the user against which the token is validated.
     * @return True if the token is valid for the user, false otherwise.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Extracts the username from a given JWT.
     *
     * @param token The JWT from which to extract the username.
     * @return The username extracted from the JWT.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a specific claim from the JWT payload using a provided claims resolver function.
     *
     * @param token           The JWT from which to extract the claim.
     * @param claimsResolver  Function to resolve the desired claim from the JWT payload.
     * @param <T>             Type of the claim.
     * @return The resolved claim value.
     */
    private <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from the JWT payload.
     *
     * @param token The JWT from which to extract all claims.
     * @return Claims object containing all the claims from the JWT payload.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(getSignKey())
                .build().parseClaimsJws(token).getBody();
    }
    /**
     * Retrieves the signing key for JWT based on the configured secret key.
     *
     * @return Key object representing the signing key.
     */
    private Key getSignKey() {
        byte[] key = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(key);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token,Claims::getExpiration).before(new Date());
    }

    @Value("${SECRET_KEY}")
    private String secretKey;
    @Value("${com.fitnessdiary.token.lifespan}")
    private long tokenLifespan;
    @Value("${com.fitnessdiary.refreshtoken.lifespan}")
    private long refreshTokenLifespan;
}
