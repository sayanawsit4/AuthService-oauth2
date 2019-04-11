package com.mykbox.domain;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Data
@Table(name = "access_audit",schema = "viomeauth2")
public class AccessAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long auditRecId;

    private String email;

}
