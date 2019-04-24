package com.mykbox.config.utils;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.regex.Pattern;

public class StringUtils {

    private static String emailRegex = "[a-zA-Z0-9\\.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";


    public static Boolean checkpassword(String plain, String hashed) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        if (BCrypt.checkpw(plain, hashed))
            return true;
        else
            return false;
    }

    public static Boolean emailFormatChecker(String email) {
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }

}