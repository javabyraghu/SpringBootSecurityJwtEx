package in.nareshit.raghu.rest;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import in.nareshit.raghu.model.Role;
import in.nareshit.raghu.model.User;
import in.nareshit.raghu.model.UserDetailsImpl;
import in.nareshit.raghu.repo.UserRepository;
import in.nareshit.raghu.request.LoginRequest;
import in.nareshit.raghu.request.SignupRequest;
import in.nareshit.raghu.response.JwtResponse;
import in.nareshit.raghu.response.MessageResponse;
import in.nareshit.raghu.util.JwtUtils;
import in.nareshit.raghu.util.RolesUtils;

@RestController
@RequestMapping("/auth")
public class AuthenticationRestController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private RolesUtils rolesUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(
			@Valid @RequestBody LoginRequest loginRequest) 
	{

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(), 
						loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		//current user data
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		//send roles in response
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(
				new JwtResponse(
						jwt, 
						userDetails.getId(), 
						userDetails.getUsername(), 
						userDetails.getEmail(), 
						roles)
				);
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
				signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> userRoles = signUpRequest.getRole();
		Set<Role> dbRoles = new HashSet<>();

		rolesUtils.mapRoles(userRoles, dbRoles);
		
		user.setRoles(dbRoles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
}
