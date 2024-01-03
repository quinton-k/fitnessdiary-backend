package com.fitnessdiary.service.auth;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

/**
 * JWTService interface provides methods for handling JSON Web Tokens (JWTs) in a Spring Security context.
 * It includes functionality for generating refresh tokens, extracting usernames from tokens,
 * generating access tokens, and validating token authenticity.
 */
public interface JWTService {

     /**
      * Generates a refresh token with optional extra claims for a given user.
      *
      * @param extraClaims Additional claims to include in the refresh token payload.
      * @param userDetails UserDetails object representing the user for whom the token is generated.
      * @return A string representing the generated refresh token.
      */
     String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails);

     /**
      * Extracts the username from a given JWT.
      *
      * @param token The JWT from which to extract the username.
      * @return The username extracted from the JWT.
      */
     String extractUsername(String token);

     /**
      * Generates an access token for a given user.
      *
      * @param userDetails UserDetails object representing the user for whom the token is generated.
      * @return A string representing the generated access token.
      */
     String generateToken(UserDetails userDetails);

     /**
      * Checks whether a given JWT is valid for a specific user.
      *
      * @param token       The JWT to be validated.
      * @param userDetails UserDetails object representing the user against which the token is validated.
      * @return True if the token is valid for the user, false otherwise.
      */
     boolean isTokenValid(String token, UserDetails userDetails);
}

