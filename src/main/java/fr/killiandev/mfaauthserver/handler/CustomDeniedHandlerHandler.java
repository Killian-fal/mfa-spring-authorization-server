package fr.killiandev.mfaauthserver.handler;

import fr.killiandev.mfaauthserver.auth.provider.NoCompletedAuthenticationToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

public class CustomDeniedHandlerHandler extends AccessDeniedHandlerImpl {

    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @Override
    public void handle(
            HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof NoCompletedAuthenticationToken noCompletedAuthenticationToken
                && !noCompletedAuthenticationToken.isAuthenticated()) {
            // clear the session and the security context
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }

            SecurityContext context = this.securityContextHolderStrategy.getContext();
            this.securityContextHolderStrategy.clearContext();
            context.setAuthentication(null);
            SecurityContext emptyContext = this.securityContextHolderStrategy.createEmptyContext();
            this.securityContextRepository.saveContext(emptyContext, request, response);

            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            // here, you an add your business logic, like redirect to a specific error page
            return;
        }

        super.handle(request, response, accessDeniedException);
    }
}
