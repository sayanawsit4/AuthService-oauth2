package com.mykbox.dto;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class changeUserActiveStatusRequest {

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private Boolean active;

}
