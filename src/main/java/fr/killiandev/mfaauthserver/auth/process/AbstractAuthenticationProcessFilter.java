package fr.killiandev.mfaauthserver.auth.process;

import fr.killiandev.mfaauthserver.auth.handler.ChainedAuthenticationHandler;
import fr.killiandev.mfaauthserver.auth.provider.NoCompletedAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * This class is used to create the filter associated with an authentication process
 * A process has always a filter to handle the authentication process, for example, verify the OTP code
 */
public abstract class AbstractAuthenticationProcessFilter extends AbstractAuthenticationProcessingFilter {

    protected AbstractAuthenticationProcessFilter(
            RequestMatcher requestMatcher,
            AuthenticationManager authenticationManager,
            ChainedAuthenticationHandler chainedAuthenticationHandler) {
        super(requestMatcher, authenticationManager);
        setAuthenticationSuccessHandler(chainedAuthenticationHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals(getHttpMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        Authentication currentAuthentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (!(currentAuthentication instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken)) {
            throw new AuthenticationServiceException("NoCompletedAuthenticationToken is not found");
        }

        // Check if the actual authentication process is the same as the current process
        // Security to prevent an user to skip the one authentication process
        // see AntiExploitAuthenticationProcessFilter also
        if (noCompletedAuthenticationToken.getActualAuthenticationProcess() != getClass()) {
            throw new AuthenticationServiceException(
                    "Actual authentication process is not " + getClass().getSimpleName());
        }

        return authenticationProcess(request, response);
    }

    /**
     * This method is used to process the authentication
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @return Authentication
     * @throws AuthenticationException
     */
    public abstract Authentication authenticationProcess(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException;

    /**
     * This method is used to get the http method of the process (in most cases POST)
     * @return String http method
     */
    public abstract String getHttpMethod();
}
