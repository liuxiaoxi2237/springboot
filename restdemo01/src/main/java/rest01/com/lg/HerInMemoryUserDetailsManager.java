package rest01.com.lg;

import java.util.Collection;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


public class HerInMemoryUserDetailsManager extends InMemoryUserDetailsManager{
    @Autowired
    private LoginAttemptService loginAttemptService;
  
    @Autowired
    private HttpServletRequest request;
    
    
	public HerInMemoryUserDetailsManager() {
		super();
	}

	public HerInMemoryUserDetailsManager(Collection<UserDetails> users) {
		super(users);
		
	}

	public HerInMemoryUserDetailsManager(UserDetails... users) {
		super(users);
		
	}

	public HerInMemoryUserDetailsManager(Properties users) {
		super(users);
	}
    
	private String getClientIP() {
	    String xfHeader = request.getHeader("X-Forwarded-For");
	    if (xfHeader == null){
	        return request.getRemoteAddr();
	    }
	    return xfHeader.split(",")[0];
	}
	
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
        String ip = getClientIP();
        if (loginAttemptService.isBlocked(ip)) {
            throw new RuntimeException("blocked");
        }
        return super.loadUserByUsername(username);
		
	}

}
