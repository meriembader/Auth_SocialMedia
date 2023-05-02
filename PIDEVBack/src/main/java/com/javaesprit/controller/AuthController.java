package com.javaesprit.controller;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.validation.Valid;

import com.javaesprit.model.User;
import com.javaesprit.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.javaesprit.dto.ApiResponse;
import com.javaesprit.dto.JwtAuthenticationResponse;
import com.javaesprit.dto.LocalUser;
import com.javaesprit.dto.LoginRequest;
import com.javaesprit.dto.SignUpRequest;
import com.javaesprit.exception.UserAlreadyExistAuthenticationException;
import com.javaesprit.security.jwt.TokenProvider;
import com.javaesprit.service.UserService;
import com.javaesprit.util.GeneralUtils;

import lombok.extern.slf4j.Slf4j;

import java.security.Principal;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	AuthenticationManager authenticationManager;
	private final JavaMailSender mailSender;

	@Autowired
	UserService userService;
	@Autowired
	PasswordEncoder pEncoder;
	@Autowired
	UserRepository userRepository;
	@Autowired
	PasswordEncoder encoder;

	@Autowired
	TokenProvider tokenProvider;

	public AuthController(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = tokenProvider.createToken(authentication);
		LocalUser localUser = (LocalUser) authentication.getPrincipal();
		return ResponseEntity.ok(new JwtAuthenticationResponse(jwt, GeneralUtils.buildUserInfo(localUser)));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
		try {
			userService.registerNewUser(signUpRequest);
		} catch (UserAlreadyExistAuthenticationException e) {
			log.error("Exception Ocurred", e);
			return new ResponseEntity<>(new ApiResponse(false, "Email Address already in use!"), HttpStatus.BAD_REQUEST);
		}
		return ResponseEntity.ok().body(new ApiResponse(true, "User registered successfully"));
	}


	@PostMapping("/change-password")
	public String changeNewPassword(@RequestParam("password") String password, @RequestBody String newPassword, Principal principal){

		PasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
		String email = principal.getName();
		User currentUser = this.userRepository.findByEmail(email);
		System.out.println(currentUser.getPassword());
		if(passwordEncoder.matches(password, currentUser.getPassword())){
			currentUser.setPassword(pEncoder.encode(newPassword));
			this.userRepository.save(currentUser);

		}else{
			return "Password is not correct";
		}
		return "Password has been changed successfully";
	}
	@PutMapping("/newPassword/{userEmail}/{newPassword}")
	public ResponseEntity resetPsassword(@PathVariable("userEmail") String userEmail, @PathVariable("newPassword") String newPassword) throws MessagingException {
		PasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
		User user = userRepository.findByEmailIgnoreCase(userEmail);
		System.out.println("hurrah==================" + newPassword);
		user.setPassword(passwordEncoder.encode(newPassword));
		userRepository.save(user);
		MimeMessage message = mailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(message, true);
		helper.setTo("ghof.bensoltane@gmail.com");
		helper.setText("<html><body><h1>Your psswd has been changed !! </h1><body></html>", true);

		helper.setSubject("Hurrah!!");
		mailSender.send(message);
		return new ResponseEntity(HttpStatus.OK);

	}
}
