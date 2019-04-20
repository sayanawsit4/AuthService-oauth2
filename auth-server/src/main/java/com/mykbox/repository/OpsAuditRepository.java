package com.mykbox.repository;

import com.mykbox.domain.AccessAudit;
import com.mykbox.domain.OperationalAudit;
import com.mykbox.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface OpsAuditRepository extends JpaRepository<OperationalAudit, UUID> {

/*
    @Query
    @Transactional
    OperationalAudit findById(UUID trackid);
*/

    
}
