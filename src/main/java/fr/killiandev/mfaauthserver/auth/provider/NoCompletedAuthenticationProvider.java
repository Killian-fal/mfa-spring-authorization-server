package fr.killiandev.mfaauthserver.auth.provider;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor
public class NoCompletedAuthenticationProvider extends DaoAuthenticationProvider {

    public NoCompletedAuthenticationProvider(PasswordEncoder passwordEncoder) {
        super(passwordEncoder);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        /*
        Here, we create a proxy token for UsernamePasswordAuthenticationToken to keep track of authentication
        but have a token with authenticated set to false.

        If a token authenticated to false is not returned, it is not possible to add steps to our
        authentication process (e.g. MFA). This exposes us to too many potential vulnerabilities.
         */
        Authentication returnAuthentication = super.authenticate(authentication);
        return new NoCompletedAuthenticationToken(
                returnAuthentication.getPrincipal(), (UsernamePasswordAuthenticationToken) returnAuthentication);
    }
}
