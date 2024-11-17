package fr.killiandev.mfaauthserver.auth.provider;

import fr.killiandev.mfaauthserver.auth.process.AbstractAuthenticationProcessFilter;
import fr.killiandev.mfaauthserver.auth.process.AbstractProcessToken;
import java.util.List;
import java.util.Objects;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * This token is used to keep track of the authentication process. It is stored in the session.
 * It is used to keep track of the original authentication and the actual authentication process.
 */
public class NoCompletedAuthenticationToken extends AbstractProcessToken {

    @Getter
    @Setter
    private Class<? extends AbstractAuthenticationProcessFilter> actualAuthenticationProcess;

    @Getter
    private final UsernamePasswordAuthenticationToken originalAuthentication; // to be restored at the end

    public NoCompletedAuthenticationToken(
            Object principal, UsernamePasswordAuthenticationToken originalAuthentication) {
        super(List.of(new SimpleGrantedAuthority("ROLE_NO_COMPLETE_AUTH")), principal, null);
        this.originalAuthentication = originalAuthentication;
        super.setAuthenticated(false); // to be sure that the token is not authenticated
    }

    @Override
    public Authentication getLinkedAuthentication() {
        return this;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        NoCompletedAuthenticationToken that = (NoCompletedAuthenticationToken) object;
        return Objects.equals(actualAuthenticationProcess, that.actualAuthenticationProcess)
                && Objects.equals(originalAuthentication, that.originalAuthentication);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), actualAuthenticationProcess, originalAuthentication);
    }
}
