package com.mykbox.repository;

import com.mykbox.domain.AccessAudit;
import com.mykbox.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditRepository extends JpaRepository<AccessAudit, String> {

    @Query
    User findByEmail(String email);
    
}
