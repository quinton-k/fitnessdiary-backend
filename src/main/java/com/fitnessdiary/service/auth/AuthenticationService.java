package com.fitnessdiary.service.auth;

import com.fitnessdiary.dto.auth.JWTAuthenticationResponse;
import com.fitnessdiary.dto.auth.RefreshTokenRequest;
import com.fitnessdiary.dto.user.SigninRequest;
import com.fitnessdiary.dto.user.SignupRequest;
import com.fitnessdiary.entity.user.User;
import org.springframework.http.HttpStatusCode;

public interface AuthenticationService {

     JWTAuthenticationResponse refreshToken(RefreshTokenRequest request);

//     JWTAuthenticationResponse refreshToken(RefreshTokenRequestDto request);

     User signup(SignupRequest request);
     JWTAuthenticationResponse signin(SigninRequest signinRequest);

     HttpStatusCode signout(RefreshTokenRequest request);
}
