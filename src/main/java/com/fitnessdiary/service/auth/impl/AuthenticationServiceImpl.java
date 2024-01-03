package com.fitnessdiary.service.auth.impl;

import com.fitnessdiary.dto.auth.JWTAuthenticationResponse;
import com.fitnessdiary.dto.auth.RefreshTokenRequest;
import com.fitnessdiary.dto.user.SigninRequest;
import com.fitnessdiary.dto.user.SignupRequest;
import com.fitnessdiary.entity.user.Role;
import com.fitnessdiary.entity.user.User;
import com.fitnessdiary.exception.DuplicateKeyException;
import com.fitnessdiary.repository.user.RoleRepository;
import com.fitnessdiary.repository.user.UserRepository;
import com.fitnessdiary.service.auth.AuthenticationService;
import com.fitnessdiary.service.auth.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    public JWTAuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String userEmail = jwtService.extractUsername(request.getToken());
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        String refreshToken = user.getRefreshToken();
        if (jwtService.isTokenValid(refreshToken,user)) {
            var jwt = jwtService.generateToken(user);

            JWTAuthenticationResponse jwtAuthenticationResponse = new JWTAuthenticationResponse();

            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRoles(user.getRoles());

            return jwtAuthenticationResponse;
        }
        return null;
    }

    public HttpStatusCode signout(RefreshTokenRequest request) {
        if (!request.getToken().isEmpty()) {
            String userEmail = jwtService.extractUsername(request.getToken());
            User user = userRepository.findByEmail(userEmail).orElseThrow();

            user.setRefreshToken(null);

            userRepository.save(user);
            return HttpStatus.OK;
        }
        return HttpStatus.NO_CONTENT;
    }
    public JWTAuthenticationResponse signin(SigninRequest signinRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signinRequest.getEmail(), signinRequest.getPassword()));
            var user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Email or Password is Invalid"));
            var jwt = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);
            var roles = user.getRoles();

            JWTAuthenticationResponse jwtAuthenticationResponse = new JWTAuthenticationResponse();

            jwtAuthenticationResponse.setToken(jwt);
            jwtAuthenticationResponse.setRoles(roles);
            user.setRefreshToken(refreshToken);

            userRepository.save(user);

            return jwtAuthenticationResponse;
        } catch (DataIntegrityViolationException e) {
            throw new BadCredentialsException("Email or password is incorrect");
        }
    }
    public User signup(SignupRequest request) {

        try {
            User user = new User();
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));

            Role defaultRole = roleRepository.findById(1)
                    .orElseThrow(() -> new IllegalStateException("Default role not found"));

            user.setRoles(Set.of(defaultRole.getId()));

            return userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new DuplicateKeyException("Account with that email is already registered.");
        }
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final RoleRepository roleRepository;

}
