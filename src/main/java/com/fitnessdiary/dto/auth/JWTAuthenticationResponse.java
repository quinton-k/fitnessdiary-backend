package com.fitnessdiary.dto.auth;

import lombok.Data;

import java.util.Set;

@Data
public class JWTAuthenticationResponse {

    private String token;
    private Set<Integer> roles;
}
