package com.mykbox.config.constants;


public final class Dto {

    //Generic Message and Status
    public static final String MESSAGE="Message";
    public static final String STATUS="status";
    public static final String UNAUTHORIZE="UnAuthorized";
    public static final String SUCESSFULL="Successfull";
    public static final String SUCESSFULL_WITH_HEADER="Successfull with header";
    public static final String NOTFOUND="NotFound";
    public static final String NOTFOUND_CLIENT="NotFound ClientId";
    public static final String FORBIDDEN="Forbidden";
    public static final String FAILURE="Failure";
    public static final String EXISTS="Exists";
    public static final String BAD_REQUEST="Bad request";
    public static final String BAD_REQUEST_CLIENT_ID="Bad Client Id";
    public static final String BAD_REQUEST_EMAIL_FORMAT="Bad Email Format";
    public static final String MALFORMED_REQ="Malformed request, could not parse or validate JSON object";
    public static final String USER_ALREADY="User active status already set to ";


    //Method :Createuser
    public static final String CREATE_USER_SUCESSFULLY = "User successfully created";
    public static final String CREATE_USER_UNAUTHORIZED ="You are not authorized to perform this action";
    public static final String CREATE_USER_FAILURE ="Unable to save user.Operation aborted";
    public static final String CREATE_USER_EXISTS="User already exists. The existing user can be activated or deactivated by customer service.";
    public static final String CREATE_USER_BAD_REQ="Invalid email format";
    public static final String CREATE_UNAUTHORIZED ="You are not authorized to perform this action";

    //Method :getAccessTokenByEmail
    public static final String ACCESS_TOKEN_BY_EMAIL_BAD_REQ_CLIENT_ID="Missing parameter: client_id.";
    public static final String ACCESS_TOKEN_BY_EMAIL_BAD_REQ_EMAIL="Invalid email format";
    public static final String ACCESS_TOKEN_BY_EMAIL_FAILURE="Unable to generate token";
    public static final String ACCESS_TOKEN_CLIENT_ID_NOT_FOUND="No application registered for this key.";


    //Method :updateUser
    public static final String UPDATE_USER_SUCESSFULLY = "user updated successfully";
    public static final String UPDATE_USER_EMAIL_BAD_REQ_EMAIL="Invalid email format";
    public static final String UPDATE_UNAUTHORIZED ="You are not authorized to perform this action";
    public static final String UPDATE_USER_NOT_FOUND ="Invalid username or password.";
    public static final String UPDATE_USER_FAILURE ="Failure";

    //Method: AuthenticateSSO
    public static final String AUTHENTICATE_SSO_INVALID_CREDS = "Invalid username or password.";
    public static final String AUTHENTICATE_SSO_FAILURE = "Failure.";
    public static final String AUTHENTICATE_SSO_CLIENT_ID_NOT_FOUND="No application registered for this key.";

    //Method :updatePassword
    public static final String UPDATE_USER_PASSWORD_SUCESSFULLY = "Password changed successfully";
    public static final String UPDATE_USER_PASSWORD_BAD_REQ_EMAIL="Invalid email format";
    public static final String UPDATE_USER_PASSWORD_FAILURE="Failed to update password";
    public static final String USER_ALREADY_SET_TRUE="User active status already set to true";
    public static final String USER_ALREADY_SET_FALSE="User active status already set to false";

    //Method :changeUserActiveStatus
    public static final String CHANGE_USER_STATUS_SUCESSFULLY = "User successfully deactivated.";
    public static final String CHANGE_USER_STATUS_FAILURE="Failed to change user status";
    public static final String CHANGE_USER_STATUS_UNAUTHORIZED ="You are not authorized to perform this action";
    public static final String CHANGE_USER_STATUS_INVALID_CREDS = "Invalid username or password.";


}