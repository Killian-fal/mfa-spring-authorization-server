package fr.killiandev.mfaauthserver.auth.process.question;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class QuestionAuthenticationTokenProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        QuestionAuthenticationToken questionAuthenticationToken = (QuestionAuthenticationToken) authentication;

        // Check if the code is correct
        if ("yes".equals(questionAuthenticationToken.getAnswer())) {
            authentication.setAuthenticated(true);
            return authentication;
        }

        throw new BadCredentialsException("Invalid answer");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return QuestionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
