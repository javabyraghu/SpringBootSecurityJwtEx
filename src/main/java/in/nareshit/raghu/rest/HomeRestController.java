package in.nareshit.raghu.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/home")
public class HomeRestController {

	@GetMapping("/all")
	public String allAccess() {
		return "Permit All Data.";
	}

	@GetMapping("/user")
	public String userAccess() {
		return "User Data.";
	}

	@GetMapping("/mod")
	public String moderatorAccess() {
		return "Moderator Data.";
	}

	@GetMapping("/admin")
	public String adminAccess() {
		return "Admin Data.";
	}
}
