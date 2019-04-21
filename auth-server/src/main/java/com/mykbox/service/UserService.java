package com.mykbox.service;

import com.mykbox.config.constants.Config;
import com.mykbox.config.constants.Dto;
import com.mykbox.config.user.ExtendedUser;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import com.mykbox.dto.updatePasswordRequest;
import com.mykbox.repository.OpsAuditRepository;
import com.mykbox.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.*;
import java.util.stream.Collectors;

import static com.mykbox.config.constants.Roles.ROLE_ADMIN;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    OpsAuditRepository opsAuditRepository;


    public Map<String,String> updatePassword(updatePasswordRequest updatePasswordRequest,
                          ExtendedUser extendedUser,
                          @SessionAttribute(Config.OPS_TRACE_ID) String trackId) {

        Map response = new HashMap();

         Optional<User> temp = findByEmail(updatePasswordRequest.getEmail());
         if (temp.isPresent()) {
            if (isPermissible(updatePasswordRequest.getEmail(), extendedUser)) {
                User user = null;
                user.setUserId(temp.get().getUserId());
                user.setPassword(new BCryptPasswordEncoder().encode(updatePasswordRequest.getNewPassword()));
                userRepository.save(user);

                OperationalAudit u = opsAuditRepository.findOne(UUID.fromString(trackId));
                u.setUserId(temp.get().getUserId());

                new ResponseEntity<>(Dto.UPDATE_SUCESSFULLY, HttpStatus.OK);

                response.put("Message",Dto.UPDATE_SUCESSFULLY);
                response.put("status","OK");

               // return response;

             } else {

                response.put("Message",Dto.UPDATE_UNAUTHORIZED);
                response.put("status","UNAUTHORIZED");
                //return response;
            }

        } else {
             response.put("Message",Dto.UPDATE_USER_NOT_FOUND);
             response.put("status","NOT_FOUND");
             //return response;
             //return new ResponseEntity<>(Dto.UPDATE_USER_NOT_FOUND,HttpStatus.NOT_FOUND);
        }
        return response;
    }

    Optional<User> findByEmail(String email) {
        return Optional.ofNullable(userRepository.findByEmail(email));
    }

    List<String> getCurrentUserRoles(ExtendedUser extendedUser) {
        return extendedUser.getAuthorities().stream().map(s -> s.getAuthority()).collect(Collectors.toList());
    }

    Boolean isPermissible(String currentEmail, ExtendedUser extendedUser) {
        return getCurrentUserRoles(extendedUser).contains(ROLE_ADMIN) || currentEmail.equals(extendedUser.getEmail());
    }
}
