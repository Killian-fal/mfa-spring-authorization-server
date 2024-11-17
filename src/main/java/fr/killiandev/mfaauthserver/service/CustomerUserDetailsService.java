package fr.killiandev.mfaauthserver.service;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.equals("user")) {
            return new User(
                    "user", "{noop}user", true, true, true, true, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        }

        throw new UsernameNotFoundException("User not found");
    }
}
