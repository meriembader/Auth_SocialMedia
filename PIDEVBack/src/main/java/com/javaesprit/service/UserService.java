package com.javaesprit.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import com.javaesprit.dto.LocalUser;
import com.javaesprit.dto.SignUpRequest;
import com.javaesprit.exception.UserAlreadyExistAuthenticationException;
import com.javaesprit.model.User;

/**
 * @author Meriem
 *
 */
public interface UserService {

	public User registerNewUser(SignUpRequest signUpRequest) throws UserAlreadyExistAuthenticationException;

	User findUserByEmail(String email);

	Optional<User> findUserById(Long id);

	LocalUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo);
}
