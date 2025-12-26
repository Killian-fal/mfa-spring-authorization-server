package fr.killiandev.mfaauthserver.auth.process.mfa;

import fr.killiandev.mfaauthserver.auth.handler.ChainedAuthenticationHandler;
import fr.killiandev.mfaauthserver.auth.process.AbstractAuthenticationProcessFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

public class MFAAuthenticationFilter extends AbstractAuthenticationProcessFilter {

    private static final String MFA_KEY = "mfa_code";
    private static final PathPatternRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/mfa");

    public MFAAuthenticationFilter(
            AuthenticationManager authenticationManager, ChainedAuthenticationHandler chainedAuthenticationHandler) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager, chainedAuthenticationHandler);

        setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/mfa?error"));
    }

    @Override
    public Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String code = request.getParameter(MFA_KEY);
        if (code == null || code.isEmpty()) {
            throw new AuthenticationServiceException("MFA code is empty");
        }

        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

        MFAAuthenticationToken mfaAuthenticationToken =
                new MFAAuthenticationToken(existingAuth.getPrincipal(), existingAuth, code);
        mfaAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(mfaAuthenticationToken);
    }

    @Override
    public String getHttpMethod() {
        return "POST";
    }
}
