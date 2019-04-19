package com.mykbox.domain;

import lombok.Data;
import org.hibernate.annotations.Generated;
import org.hibernate.annotations.GenerationTime;
import org.hibernate.validator.constraints.Email;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

@Entity
@Data
@Table(name = "user",schema = "viomeauth2")
public class User {

  	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
 	@org.hibernate.annotations.Type(type="pg-uuid")
	@Column(name = "user_id")
	private UUID userId;

/*	@Size(min = 0, max = 50)
	private String username;*/

	@Size(min = 0, max = 500)
	private String password;

	@Email
	@Size(min = 0, max = 50)
	private String email;

	private boolean activated;

	@Size(min = 0, max = 100)
	@Column(name = "first_name")
	private String first_name;

	@Size(min = 0, max = 100)
	@Column(name = "last_nme")
	private String lastName;

/*	@Size(min = 0, max = 100)
	@Column(name = "activationkey")
	private String activationKey;

	@Size(min = 0, max = 100)
	@Column(name = "resetpasswordkey")
	private String resetPasswordKey;

	@Column(name = "phone")
	private Long phone;

	@Column(name = "providerId")
	private String providerId;*/

	@ManyToMany
	@JoinTable(name = "user_authority", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "authority"))
	private Set<Authority> authorities;
}