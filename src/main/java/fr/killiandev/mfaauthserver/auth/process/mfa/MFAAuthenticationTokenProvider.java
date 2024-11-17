package fr.killiandev.mfaauthserver.auth.process.mfa;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class MFAAuthenticationTokenProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MFAAuthenticationToken mfaAuthenticationToken = (MFAAuthenticationToken) authentication;

        // Check if the code is correct
        if ("1234".equals(mfaAuthenticationToken.getCode())) {
            authentication.setAuthenticated(true);
            return authentication;
        }

        throw new BadCredentialsException("Invalid code");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MFAAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
