package fr.killiandev.mfaauthserver.auth.process.question;

import fr.killiandev.mfaauthserver.auth.handler.ChainedAuthenticationProcess;
import fr.killiandev.mfaauthserver.auth.process.AbstractAuthenticationProcessFilter;
import fr.killiandev.mfaauthserver.auth.process.mfa.MFAAuthenticationToken;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;

public class QuestionAuthenticationProcess implements ChainedAuthenticationProcess {

    /*
     * This class is an example, if you want more explanation, please refer to the MFAAuthenticationProcess.java
     */

    @Override
    public Class<? extends AbstractAuthenticationProcessFilter> getFilterClass() {
        return QuestionAuthenticationFilter.class;
    }

    @Override
    public boolean needToProcess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest)
            throws ServletException, IOException {
        return true;
    }

    @Override
    public boolean isTheNext(Authentication authentication) {
        return authentication instanceof MFAAuthenticationToken;
    }

    @Override
    public String getProcessUri() {
        return "/question";
    }

    @Override
    public String getProcessQuery(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            SavedRequest savedRequest) {
        return null;
    }
}
