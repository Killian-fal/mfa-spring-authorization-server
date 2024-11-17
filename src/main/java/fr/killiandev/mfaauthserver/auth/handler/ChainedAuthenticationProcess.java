package fr.killiandev.mfaauthserver.auth.handler;

import fr.killiandev.mfaauthserver.auth.process.AbstractAuthenticationProcessFilter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;

public interface ChainedAuthenticationProcess {

    /**
     * @return the filter class of the process
     */
    Class<? extends AbstractAuthenticationProcessFilter> getFilterClass();

    /**
     * @param request the current request
     * @param response the current response
     * @param authentication the current authentication
     * @param savedRequest the saved request
     * @return true if the process need to be processed
     */
    boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException;

    /**
     * @param authentication the current authentication
     * @return true if the current authentication is authentication before this process
     */
    boolean isTheNext(Authentication authentication);

    /**
     * @return the uri of the process which will be used to redirect the user
     */
    String getProcessUri();

    /**
     * @return the query of the process which will be used to redirect the user (null if no query args)
     */
    String getProcessQuery(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest);
}
