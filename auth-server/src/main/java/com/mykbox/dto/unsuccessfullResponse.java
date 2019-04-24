package com.mykbox.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class unsuccessfullResponse {

    String error;
    String errorDescription;
    List<String> listoferrorDescription;

    public unsuccessfullResponse(String error,String errorDescription)
    {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public unsuccessfullResponse(String error,List<String> listoferrorDescription)
    {
        this.error = error;
        this.listoferrorDescription = listoferrorDescription;
    }


}
