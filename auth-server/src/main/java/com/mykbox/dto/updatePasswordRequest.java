package com.mykbox.dto;

import lombok.Data;

import javax.validation.constraints.NotNull;

@Data
public class updatePasswordRequest {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String email;
    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private  String newPassword;
}
