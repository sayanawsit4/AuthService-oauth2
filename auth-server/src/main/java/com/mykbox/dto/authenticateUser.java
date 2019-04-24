package com.mykbox.dto;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotNull;
import java.util.Optional;

@Data
public class authenticateUser {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String password;

    @Builder.Default
    private String clientId = "";
}
