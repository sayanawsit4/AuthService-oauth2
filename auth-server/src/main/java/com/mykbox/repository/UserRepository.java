package com.mykbox.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import com.mykbox.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

//    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:username)")
//    User findByUsernameCaseInsensitive(@Param("username") String username);

    @Query
    User findByEmail(String email);
    
}
