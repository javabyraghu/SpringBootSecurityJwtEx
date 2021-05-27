package in.nareshit.raghu.response;

import java.util.List;

import lombok.Data;
import lombok.NonNull;

@Data
public class JwtResponse {
	
	@NonNull
	private String token;
	
	private String type = "Bearer";
	
	@NonNull
	private Long id;
	
	@NonNull
	private String username;
	
	@NonNull
	private String email;
	
	@NonNull
	private List<String> roles;

}
