package com.mykbox.repository;

import com.mykbox.domain.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

public interface TokenRepository  extends JpaRepository<AccessToken, Long> {

    @Transactional
    @Modifying
    @Query("delete from AccessToken t where t.expiration <= ?1")
    void deleteAllExpiredSince(Date now);

    @Transactional
    @Query("select userName from AccessToken t where t.tokenId = ?1")
    String findUsernameByToken(String token);

}
