package com.mykbox.dto;

import lombok.Data;

@Data
public class updatePasswordRequest {

    private String email;
    private  String newPassword;
}
