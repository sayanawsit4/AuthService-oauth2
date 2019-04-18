package com.mykbox.dto;

import lombok.Data;

import java.util.UUID;

@Data
public class userResponse {

    private UUID userId;
    private String username;
    private String email;
    private String first_name;
    private String last_name;

}
