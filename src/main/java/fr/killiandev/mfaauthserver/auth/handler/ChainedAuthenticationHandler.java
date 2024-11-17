package fr.killiandev.mfaauthserver.auth.handler;

import fr.killiandev.mfaauthserver.auth.process.AbstractAuthenticationProcessFilter;
import fr.killiandev.mfaauthserver.auth.process.AbstractProcessToken;
import fr.killiandev.mfaauthserver.auth.provider.NoCompletedAuthenticationToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;

@RequiredArgsConstructor
public class ChainedAuthenticationHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final List<ChainedAuthenticationProcess> processes;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        String targetUrlParameter = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl()
                || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
            this.requestCache.removeRequest(request, response);
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        clearAuthenticationAttributes(request);

        if (!authentication.isAuthenticated() && !(authentication instanceof NoCompletedAuthenticationToken)) {
            throw new AuthenticationServiceException("Authentication token is not authenticated");
        }

        // Use the DefaultSavedRequest URL
        String targetUrl = savedRequest.getRedirectUrl();

        boolean hasNext = false;
        for (ChainedAuthenticationProcess process : processes) {
            if (process.isTheNext(authentication)) {
                if (process.needToProcess(request, response, authentication, savedRequest)) {
                    hasNext = true;
                    targetUrl = buildProcessUri(request, response, authentication, savedRequest, process);
                    updateToNoCompletedToken(authentication, process.getFilterClass());
                }
                break;
            }
        }

        if (!hasNext) {
            // If there is no next process, restore the original authentication token
            // (UsernamePasswordAuthenticationToken)
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(extractOriginalAuthentication(authentication));
            securityContextRepository.saveContext(context, request, response);
        }

        // Redirect to the next step (process or OAuth2)
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /**
     * Build the process URI
     *
     * @param request the current request
     * @param response the current response
     * @param authentication the current authentication
     * @param savedRequest the saved request
     * @param process the current process
     * @return the process URI
     */
    private String buildProcessUri(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest,
            ChainedAuthenticationProcess process) {
        return UrlUtils.buildFullRequestUrl(
                request.getScheme(),
                request.getServerName(),
                request.getServerPort(),
                process.getProcessUri(),
                process.getProcessQuery(request, response, authentication, savedRequest));
    }

    /**
     * Extract the original authentication token (UsernamePasswordAuthenticationToken) from the current authentication
     *
     * @param authentication the current authentication
     * @return the original authentication token
     */
    private Authentication extractOriginalAuthentication(Authentication authentication) {
        if (authentication instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken) {
            return noCompletedAuthenticationToken.getOriginalAuthentication();
        }

        if (authentication instanceof AbstractProcessToken processToken) {
            return extractOriginalAuthentication(processToken.getLinkedAuthentication());
        }

        throw new AuthenticationServiceException(
                "Unable to find the original authentication token (UsernamePasswordAuthenticationToken)");
    }

    /**
     * Update the NoCompletedAuthenticationToken actual process to the next process
     * Usefully to verify that the user does not skip any process
     *
     * @param authentication the current authentication
     * @param filterClass the next process filter class
     */
    private void updateToNoCompletedToken(
            Authentication authentication, Class<? extends AbstractAuthenticationProcessFilter> filterClass) {
        if (authentication instanceof AbstractProcessToken processToken
                && processToken.getLinkedAuthentication()
                        instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken) {
            noCompletedAuthenticationToken.setActualAuthenticationProcess(filterClass);
        } else {
            throw new AuthenticationServiceException("Unable to find the NoCompletedAuthenticationToken");
        }
    }
}
