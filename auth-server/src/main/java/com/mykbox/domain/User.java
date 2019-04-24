package com.mykbox.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Generated;
import org.hibernate.annotations.GenerationTime;
import org.hibernate.validator.constraints.Email;
import org.springframework.beans.factory.annotation.Required;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.Set;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "user",schema = "viomeauth2")
public class User {

  	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
 	@org.hibernate.annotations.Type(type="pg-uuid")
	@Column(name = "user_id")
	private UUID userId;

	@Size(min = 0, max = 500)
	private String password;

	@Email
	@Size(min = 0, max = 50)
	private String email;

	private boolean activated = true;

	@Size(min = 0, max = 100)
	@Column(name = "first_name")
	private String firstName;

	@Size(min = 0, max = 100)
	@Column(name = "last_name")
	private String lastName;

	@ManyToMany
	@JoinTable(name = "user_authority", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "authority"))
	private Set<Authority> authorities;
}