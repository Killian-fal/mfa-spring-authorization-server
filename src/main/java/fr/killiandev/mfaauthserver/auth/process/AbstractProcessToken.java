package fr.killiandev.mfaauthserver.auth.process;

import java.util.Collection;
import java.util.Objects;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@Getter
public abstract class AbstractProcessToken extends AbstractAuthenticationToken {

    private final Object principal;

    // linkedAuthentication is the previous authentication that was used to authenticate the user
    // normally is an instance of NoCompletedAuthenticationToken
    private final Authentication linkedAuthentication;

    protected AbstractProcessToken(
            Collection<? extends GrantedAuthority> authorities, Object principal, Authentication linkedAuthentication) {
        super(authorities);
        this.principal = principal;
        this.linkedAuthentication = linkedAuthentication;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        AbstractProcessToken that = (AbstractProcessToken) object;
        return Objects.equals(principal, that.principal)
                && Objects.equals(linkedAuthentication, that.linkedAuthentication);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), principal, linkedAuthentication);
    }
}
