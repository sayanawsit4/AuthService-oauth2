package com.mykbox.controller;

import com.mykbox.config.constants.Config;
import com.mykbox.config.constants.Dto;
import com.mykbox.config.constants.Token;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.dto.*;
import com.mykbox.service.TokenService;
import com.mykbox.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.mykbox.config.constants.Roles.ROLE_ADMIN;
import static com.mykbox.config.constants.Roles.ROLE_USER;
import static com.mykbox.config.utils.StringUtils.checkpassword;
import static com.mykbox.config.utils.StringUtils.emailFormatChecker;

@RestController
@Api(value = "Authentication API", description = "Authenticate user using authorization token.")

public class ResourceController {

    @Value("${token.validity}")
    private Integer validity;

    @Value("${ApplicationMode}")
    private String ApplicationMode;

    @Autowired
    UserService userService;

    @Autowired
    TokenService tokenService;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity handleValidationExceptions(MethodArgumentNotValidException ex) {

        List<String> errorlist = ex.getBindingResult()
                .getAllErrors().stream()
                .map(ObjectError::getDefaultMessage)
                .collect(Collectors.toList());

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                return new ResponseEntity<>(Dto.MALFORMED_REQ, HttpStatus.BAD_REQUEST);
            default:
                return new ResponseEntity<>(new unsuccessfullResponse(Dto.BAD_REQUEST, errorlist), HttpStatus.BAD_REQUEST);
        }
    }

    // TODO: 4/18/2019 legacy
    @RequestMapping("/api/createUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.CREATE_USER_SUCESSFULLY, response = String.class),
            @ApiResponse(code = 401, message = Dto.CREATE_USER_UNAUTHORIZED),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity createUser(@RequestBody @Valid UserRequest user,
                                     @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                     OAuth2Authentication auth) {

        String responseObj;

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        //Revoke token if one-time
        tokenService.revokeToken(accessToken, details);

        if (emailFormatChecker(user.getEmail())) {
            responseObj = userService.createUser(user, trackId, (ExtendedUser) auth.getPrincipal());
        } else {
            responseObj = Dto.BAD_REQUEST;
        }

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(Dto.CREATE_USER_SUCESSFULLY, HttpStatus.OK);
                    case Dto.EXISTS:
                        return new ResponseEntity<>(Dto.CREATE_USER_EXISTS, HttpStatus.OK);
                    case Dto.BAD_REQUEST:
                        return new ResponseEntity<>(Dto.CREATE_USER_BAD_REQ, HttpStatus.BAD_REQUEST);
                    case Dto.UNAUTHORIZE:
                        return new ResponseEntity<>(Dto.CREATE_USER_UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.CREATE_USER_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.NOTFOUND, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new successfullResponse(Dto.SUCESSFULL, Dto.CREATE_USER_SUCESSFULLY), HttpStatus.OK);
                    case Dto.EXISTS:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.CREATE_USER_EXISTS), HttpStatus.OK);
                    case Dto.UNAUTHORIZE:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.CREATE_UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
                    case Dto.BAD_REQUEST:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.CREATE_USER_BAD_REQ), HttpStatus.BAD_REQUEST);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.NOTFOUND), HttpStatus.NOT_FOUND);
                }
        }
    }

    // TODO: 2/28/2019 :protect this endpoint with xauth headers as per AuthService 1.0 implementation
    @RequestMapping(value = "/getAccessTokenByEmail", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.SUCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    public @ResponseBody
    ResponseEntity gettoken(
            @RequestBody @Valid TokenRequest tokenRequest,
            @RequestParam(value = "expiry_extension", required = false) Optional<Integer> expiryExtension,
            @RequestParam(value = "client_id", required = false) Optional<String> clientId
    ) {
        Integer extendedValidity;
        String scope = Token.AD_HOC;
        String responseObj;
        OAuth2AccessToken token = null;

        if (emailFormatChecker(tokenRequest.getEmail())) {
            if (clientId.isPresent()) {
                if (tokenService.checkClientId(clientId.get())) {
                    if (expiryExtension.isPresent()) {
                        if (expiryExtension.get().equals(0)) {
                            scope = Token.ONE_TIME;
                            extendedValidity = 0;
                        } else {
                            scope = Token.AD_HOC_EXTN;
                            extendedValidity = validity + expiryExtension.get();
                        }
                    } else
                        extendedValidity = validity;

                    ExtendedUser ext = userService.loadextendedUserByEmail(tokenRequest.getEmail());
                    try {
                        token = tokenService.createToken(extendedValidity, ext, scope, clientId.get());
                        responseObj = Dto.SUCESSFULL;
                    } catch (Exception e) {
                        responseObj = Dto.FAILURE;
                    }

                } else {
                    responseObj = Dto.NOTFOUND;
                }

            } else {
                responseObj = Dto.BAD_REQUEST_CLIENT_ID;
            }
        } else {
            responseObj = Dto.BAD_REQUEST_EMAIL_FORMAT;
        }

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(token.getValue(), HttpStatus.OK);
                    case Dto.BAD_REQUEST_CLIENT_ID:
                        return new ResponseEntity<>(Dto.ACCESS_TOKEN_BY_EMAIL_BAD_REQ_CLIENT_ID, HttpStatus.BAD_REQUEST);
                    case Dto.BAD_REQUEST_EMAIL_FORMAT:
                        return new ResponseEntity<>(Dto.ACCESS_TOKEN_BY_EMAIL_BAD_REQ_EMAIL, HttpStatus.BAD_REQUEST);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.ACCESS_TOKEN_BY_EMAIL_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.ACCESS_TOKEN_CLIENT_ID_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new successfullResponse(Dto.SUCESSFULL, token.getValue()), HttpStatus.OK);
                    case Dto.BAD_REQUEST_CLIENT_ID:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.ACCESS_TOKEN_BY_EMAIL_BAD_REQ_CLIENT_ID), HttpStatus.BAD_REQUEST);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.ACCESS_TOKEN_CLIENT_ID_NOT_FOUND), HttpStatus.NOT_FOUND);
                }
        }

    }


    // TODO: 4/18/2019 legacy
    @RequestMapping("/api/updateUser")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.SUCESSFULL, response = String.class),
            @ApiResponse(code = 401, message = Dto.UNAUTHORIZE),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updateUser(@RequestBody @Valid updateUserRequest updateUserRequest,
                                     @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                     OAuth2Authentication auth) {

        String responseObj;

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        //Revoke token if one-time
        tokenService.revokeToken(accessToken, details);

        if (emailFormatChecker(updateUserRequest.getEmail())) {
            responseObj = userService.updateUser(updateUserRequest, trackId, (ExtendedUser) auth.getPrincipal());
        } else {
            responseObj = Dto.BAD_REQUEST;
        }

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(Dto.UPDATE_USER_SUCESSFULLY, HttpStatus.OK);
                    case Dto.BAD_REQUEST:
                        return new ResponseEntity<>(Dto.UPDATE_USER_EMAIL_BAD_REQ_EMAIL, HttpStatus.BAD_REQUEST);
                    case Dto.UNAUTHORIZE:
                        return new ResponseEntity<>(Dto.UPDATE_UNAUTHORIZED, HttpStatus.UNAUTHORIZED);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.UPDATE_USER_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.UPDATE_USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new successfullResponse(Dto.SUCESSFULL, Dto.UPDATE_USER_SUCESSFULLY), HttpStatus.OK);
                    case Dto.UNAUTHORIZE:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
                    case Dto.BAD_REQUEST:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_USER_EMAIL_BAD_REQ_EMAIL), HttpStatus.BAD_REQUEST);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_USER_NOT_FOUND), HttpStatus.NOT_FOUND);
                }
        }

    }

    @RequestMapping(method = RequestMethod.POST, value = "/authenticateSSO")
    public @ResponseBody
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.SUCESSFULL, response = String.class),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    ResponseEntity authenticateSSO(@RequestBody @Valid authenticateUser authenticateUser,
                                   HttpServletResponse response) {

        String responseObj;

        if (emailFormatChecker(authenticateUser.getEmail())) {
            if (userService.findByEmail(authenticateUser.getEmail()).isPresent()) {
                ExtendedUser ext = userService.loadextendedUserByEmail(authenticateUser.getEmail());
                if (checkpassword(authenticateUser.getPassword(), ext.getPassword())) {
                    if (!authenticateUser.getClientId().isEmpty()) {
                        if (tokenService.checkClientId(authenticateUser.getClientId())) {
                            try {
                                OAuth2AccessToken token = tokenService.createToken(validity, ext, Token.AD_HOC_AUTH_SSO, authenticateUser.getClientId());
                                response.addHeader("token", token.getValue());
                                responseObj = Dto.SUCESSFULL_WITH_HEADER;
                            } catch (Exception e) {
                                responseObj = Dto.FAILURE;
                            }
                        } else {
                            responseObj = Dto.NOTFOUND_CLIENT;
                        }
                    } else {
                        responseObj = Dto.SUCESSFULL;
                    }
                } else {
                    responseObj = Dto.NOTFOUND;
                }
            } else {
                responseObj = Dto.NOTFOUND;
            }
        } else {
            responseObj = Dto.NOTFOUND;
        }

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(authenticateUser.getEmail(), HttpStatus.OK);
                    case Dto.SUCESSFULL_WITH_HEADER:
                        return new ResponseEntity<>(authenticateUser.getEmail(), HttpStatus.OK);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.AUTHENTICATE_SSO_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    case Dto.NOTFOUND_CLIENT:
                        return new ResponseEntity<>(Dto.AUTHENTICATE_SSO_CLIENT_ID_NOT_FOUND, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.AUTHENTICATE_SSO_INVALID_CREDS, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new successfullResponse(Dto.SUCESSFULL, authenticateUser.getEmail()), HttpStatus.OK);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_USER_NOT_FOUND), HttpStatus.NOT_FOUND);
                }
        }
    }


    @RequestMapping(value = "/api/changeUserActiveStatus", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.SUCESSFULL, response = String.class),
            @ApiResponse(code = 401, message = Dto.UNAUTHORIZE),
            @ApiResponse(code = 404, message = Dto.NOTFOUND),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity changeUserActiveStatus(@RequestBody @Valid changeUserActiveStatusRequest changeUserActiveStatusRequest,
                                                 @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                                 OAuth2Authentication auth) {

        String responseObj;


        if (emailFormatChecker(changeUserActiveStatusRequest.getEmail())) {
            responseObj = userService.changeUserStatus(changeUserActiveStatusRequest, trackId, (ExtendedUser) auth.getPrincipal());
        } else {
            responseObj = Dto.BAD_REQUEST;
        }

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(Dto.CHANGE_USER_STATUS_SUCESSFULLY, HttpStatus.OK);
                    case Dto.USER_ALREADY_SET_TRUE:
                        return new ResponseEntity<>(Dto.USER_ALREADY_SET_TRUE, HttpStatus.OK);
                    case Dto.USER_ALREADY_SET_FALSE:
                        return new ResponseEntity<>(Dto.USER_ALREADY_SET_FALSE, HttpStatus.OK);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.CHANGE_USER_STATUS_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.CHANGE_USER_STATUS_INVALID_CREDS, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new updateResponse(Dto.SUCESSFULL), HttpStatus.OK);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_USER_NOT_FOUND), HttpStatus.NOT_FOUND);
                }
        }

    }

    // TODO: 4/18/2019 legacy
    @ApiOperation(value = "Update password", response = String.class)
    @RequestMapping(value = "/api/updatePassword", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = Dto.SUCESSFULL, response = String.class),
            @ApiResponse(code = 401, message = Dto.UPDATE_UNAUTHORIZED),
            @ApiResponse(code = 404, message = Dto.UPDATE_USER_NOT_FOUND),
            @ApiResponse(code = 500, message = Dto.FAILURE)})
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_USER + "')")
    public ResponseEntity updatePassword(@RequestBody @Valid updatePasswordRequest updatePasswordRequest,
                                         @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                         OAuth2Authentication auth) {

        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        //Revoke token if one-time
        tokenService.revokeToken(accessToken, details);

        String responseObj;

        if (emailFormatChecker(updatePasswordRequest.getEmail())) {
            responseObj = userService.updatePassword(updatePasswordRequest, (ExtendedUser) auth.getPrincipal(), trackId);

        } else {
            responseObj = Dto.BAD_REQUEST;
        }

        tokenService.UpdateOperationalAudit(trackId,
                responseObj,
                (ExtendedUser) auth.getPrincipal(),
                accessToken.getScope().stream().map(Object::toString).collect(Collectors.joining(",")));

        switch (ApplicationMode) {
            case Config.LEGACY_APP_MODE:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(Dto.UPDATE_USER_PASSWORD_SUCESSFULLY, HttpStatus.OK);
                    case Dto.BAD_REQUEST:
                        return new ResponseEntity<>(Dto.UPDATE_USER_PASSWORD_BAD_REQ_EMAIL, HttpStatus.BAD_REQUEST);
                    case Dto.FAILURE:
                        return new ResponseEntity<>(Dto.UPDATE_USER_PASSWORD_FAILURE, HttpStatus.INTERNAL_SERVER_ERROR);
                    default:
                        return new ResponseEntity<>(Dto.AUTHENTICATE_SSO_INVALID_CREDS, HttpStatus.NOT_FOUND);
                }
            default:
                switch (responseObj) {
                    case Dto.SUCESSFULL:
                        return new ResponseEntity<>(new updateResponse(Dto.SUCESSFULL), HttpStatus.OK);
                    default:
                        return new ResponseEntity<>(new unsuccessfullResponse(responseObj, Dto.UPDATE_USER_NOT_FOUND), HttpStatus.NOT_FOUND);
                }
        }
    }


    @RequestMapping("/api/user")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public userResponse user(Principal user, OAuth2Authentication auth) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(details.getTokenValue());

        //Revoke token if one-time
        tokenService.revokeToken(accessToken, details);

        ExtendedUser extendedUser = (ExtendedUser) auth.getPrincipal();
        userResponse userResponse = new userResponse();
        userResponse.setUserId(extendedUser.getUserid());
        userResponse.setUsername(extendedUser.getEmail());
        userResponse.setEmail(extendedUser.getEmail());
        userResponse.setFirst_name(extendedUser.getfirstName());
        userResponse.setLast_name(extendedUser.getlastName());

        return userResponse;
    }

}