package com.mykbox.domain;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.validator.constraints.Email;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Data
@Entity
@Table(name = "operational_audit", schema = "viomeauth2")
public class OperationalAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @org.hibernate.annotations.Type(type="pg-uuid")
    @Column(name = "ops_audit_rec_no")
    private UUID opsAuditNo;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "token_id")
    private String tokenId;

    @Column(name = "ops_performed_by")
    private UUID opsPerformedBy;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "created_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdTime;

    @Column(name = "remote_ip")
    private String remoteIP;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "url")
    private String url;

    @Column(name = "status")
    private String status;

    @Column(name = "scope")
    private String scope;

    @Column(name = "response")
    private String response;
/*
    @Column(name = "created_time")
    @CreationTimestamp
    private LocalDateTime createDateTime;*/


}