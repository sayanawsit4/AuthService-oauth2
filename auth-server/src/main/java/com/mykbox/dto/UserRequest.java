package com.mykbox.dto;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class UserRequest {

    private String email;

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    @Size(min = 1, max = 60)
    private String firstName;
    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String lastName;

    private String password;

   //TODO this properties to support legacy clients.This values doesnt get persisted at all.Should be deprecated.

    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private Long phone;
    @NotNull(message = "Malformed request, could not parse or validate JSON object.")
    private String providerId;


}
