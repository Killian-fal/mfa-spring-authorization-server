package fr.killiandev.mfaauthserver.auth.process.question;

import fr.killiandev.mfaauthserver.auth.process.AbstractProcessToken;
import java.util.Objects;
import lombok.Getter;
import org.springframework.security.core.Authentication;

public class QuestionAuthenticationToken extends AbstractProcessToken {

    @Getter
    private final String answer;

    public QuestionAuthenticationToken(Object principal, Authentication linkedAuthentication, String answer) {
        super(null, principal, linkedAuthentication);
        this.answer = answer;
        super.setAuthenticated(false); // to be sure that the token is not authenticated
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        if (!super.equals(object)) return false;
        QuestionAuthenticationToken that = (QuestionAuthenticationToken) object;
        return Objects.equals(answer, that.answer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), answer);
    }
}
