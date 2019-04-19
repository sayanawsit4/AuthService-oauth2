package com.mykbox.config.user;

import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.UUID;

public class ExtendedUser extends User{

    private final String email;
    private final UUID userid;
    private final String firstName;
    private final String lastName;

    public ExtendedUser(String username,String password, boolean enabled,
                        boolean accountNonExpired, boolean credentialsNonExpired,
                        boolean accountNonLocked,
                        Collection authorities,
                        String email,
                        UUID userid,
                        String firstName,
                        String lastName) {

        super(username, password, enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, authorities);

        this.email = email;
        this.userid= userid;
        this.firstName = firstName;
        this.lastName= lastName;
    }

    public String getEmail() {
        return email;
    }
    public UUID getUserid() {
        return userid;
    }
    public String getfirstName() {
        return firstName;
    }
    public String getlastName() {
        return lastName;
    }


}
