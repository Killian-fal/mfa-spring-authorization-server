package fr.killiandev.mfaauthserver.auth.process.question;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class QuestionController {

    @GetMapping("/question")
    public String authenticator() {
        return "question";
    }
}
