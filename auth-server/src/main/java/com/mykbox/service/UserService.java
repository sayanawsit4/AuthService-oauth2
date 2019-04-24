package com.mykbox.service;

import com.mykbox.config.constants.Config;
import com.mykbox.config.constants.Dto;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.dto.UserRequest;
import com.mykbox.dto.changeUserActiveStatusRequest;
import com.mykbox.dto.updatePasswordRequest;
import com.mykbox.dto.updateUserRequest;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.mykbox.config.constants.Roles.ROLE_ADMIN;

@Service
public class UserService {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    OpsAuditRepository opsAuditRepository;

    public String createUser(UserRequest user,
                             @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                             ExtendedUser extendedUser) {

        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));

        String response;

        if (temp.isPresent()) {
            response = Dto.EXISTS;
        } else {
            if (isPermissible(user.getEmail(), extendedUser)) {
                try {
                    userRepository.save(new User(null, user.getPassword(), user.getEmail(), true, user.getFirstName(), user.getLastName(), null));
                    response = Dto.SUCESSFULL;
                } catch (Exception e) {
                    response = Dto.FAILURE;
                }
            } else {
                response = Dto.UNAUTHORIZE;
            }
        }

        return response;
    }

    public String changeUserStatus(changeUserActiveStatusRequest user,
                                   @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                                   ExtendedUser extendedUser) {

        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));

        String response;

        if (temp.isPresent()) {
             if (temp.get().isActivated() == user.getActive()) {
                response = Dto.USER_ALREADY + temp.get().isActivated();
                System.out.println(response);
            } else {
                try {
                     userRepository.save(new User(temp.get().getUserId(),
                            temp.get().getPassword(),
                            temp.get().getEmail(),
                            user.getActive(),
                            temp.get().getFirstName(),
                            temp.get().getLastName(),
                            temp.get().getAuthorities()));
                    response = Dto.SUCESSFULL;
                } catch (Exception e) {
                    response = Dto.FAILURE;
                }
             }

        } else {
            response = Dto.NOTFOUND;
        }
         return response;
    }

    public String updateUser(updateUserRequest user,
                             @SessionAttribute(Config.OPS_TRACE_ID) String trackId,
                             ExtendedUser extendedUser) {

        Optional<User> temp = Optional.ofNullable(userRepository.findByEmail(user.getEmail()));
        String response = null;
         if (temp.isPresent()) {
            if (isPermissible(user.getEmail(), extendedUser)) {
                 try {
                    userRepository.save(new User(temp.get().getUserId(),
                            temp.get().getPassword(),
                            temp.get().getEmail(),
                            temp.get().isActivated(),
                            user.getFirstName(),
                            user.getLastName(),
                            temp.get().getAuthorities()));
                } catch (Exception e) {
                    response = Dto.FAILURE;
                }
                response = Dto.SUCESSFULL;
            }
        } else {
            response = Dto.NOTFOUND;
        }

        return response;
    }

    public String updatePassword(updatePasswordRequest updatePasswordRequest,
                                 ExtendedUser extendedUser,
                                 @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {

        String response;
        Optional<User> temp = findByEmail(updatePasswordRequest.getEmail());
        if (temp.isPresent()) {
            if (isPermissible(updatePasswordRequest.getEmail(), extendedUser)) {
                User user = temp.get();
                user.setUserId(temp.get().getUserId());
                user.setPassword(new BCryptPasswordEncoder().encode(updatePasswordRequest.getNewPassword()));
                userRepository.save(user);

                response = Dto.SUCESSFULL;

            } else {
                response = Dto.UNAUTHORIZE;
            }

        } else {
            response = Dto.NOTFOUND;
        }

        OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
        u.setUserId(temp.get().getUserId());

        return response;
    }

    public Optional<User> findByEmail(String email) {
        return Optional.ofNullable(userRepository.findByEmail(email));
    }

    List<String> getCurrentUserRoles(ExtendedUser extendedUser) {
        return extendedUser.getAuthorities().stream().map(s -> s.getAuthority()).collect(Collectors.toList());
    }

    Boolean isPermissible(String currentEmail, ExtendedUser extendedUser) {
        return getCurrentUserRoles(extendedUser).contains(ROLE_ADMIN) || currentEmail.equals(extendedUser.getEmail());
    }


    public ExtendedUser loadextendedUserByEmail(String email)
     {
         return  (ExtendedUser)userDetailsService.loadUserByUsername(email);
     }
}