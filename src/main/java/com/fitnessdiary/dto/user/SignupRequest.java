package com.fitnessdiary.dto.user;

import lombok.Data;

@Data
public class SignupRequest {

    private String email;
    private String password;
}
