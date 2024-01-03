package com.fitnessdiary.controller.auth;

import com.fitnessdiary.dto.auth.JWTAuthenticationResponse;
import com.fitnessdiary.dto.auth.RefreshTokenRequest;
import com.fitnessdiary.dto.user.SigninRequest;
import com.fitnessdiary.dto.user.SignupRequest;
import com.fitnessdiary.exception.DuplicateKeyException;
import com.fitnessdiary.service.auth.AuthenticationService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthenticationController {

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequest signupRequest) {
        try {
            authenticationService.signup(signupRequest);
            return ResponseEntity.ok("Account registered successfully");
        } catch (DuplicateKeyException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<JWTAuthenticationResponse> signin(@RequestBody SigninRequest signinRequest, HttpServletResponse response) {
        try {
            JWTAuthenticationResponse authenticationResponse = authenticationService.signin(signinRequest);

            ResponseCookie cookie = ResponseCookie.from("Token", authenticationResponse.getToken())
                    .httpOnly(true)
                    .secure(true)
                    .domain("localhost")
                    .path("/")
                    .sameSite("Lax")
                    .build();
            response.setHeader(HttpHeaders.SET_COOKIE,cookie.toString());

            return ResponseEntity.ok(authenticationResponse);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/refresh")
    public ResponseEntity<JWTAuthenticationResponse> refresh(@CookieValue(value = "Token", defaultValue = "") String token, HttpServletResponse response) {
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();

        refreshTokenRequest.setToken(token);

        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }

    @GetMapping("/signout")
    public ResponseEntity<HttpStatus> signout(@CookieValue(value = "Token", defaultValue = "") String token,HttpServletResponse response) {
        RefreshTokenRequest tokenRequest = new RefreshTokenRequest();

        tokenRequest.setToken(token);

        ResponseEntity<HttpStatus> responseStatus = ResponseEntity.status(authenticationService.signout(tokenRequest)).build();
        Cookie cookie = new Cookie("Token", null);
        cookie.setMaxAge(0); // Set the cookie's maximum age to 0, effectively deleting it
        cookie.setPath("/"); // Set the cookie's path to match the one used when creating the cookie
        response.addCookie(cookie);


        return responseStatus;
    }

    private final AuthenticationService authenticationService;
}
