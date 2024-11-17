package fr.killiandev.mfaauthserver;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class MfaauthserverApplicationTests {

    private static final String QUERY =
            "response_type=code&client_id=client&scope=openid&redirect_uri=https://oauth.pstmn.io/v1/callback&code_challenge=N4MAVFaaMVGKul-IRn59dmZ6JI62MmEN_pDRYMiNxTg&code_challenge_method=S256";

    private static final String URL =
            UrlUtils.buildFullRequestUrl("http", "localhost", 9000, "/oauth2/authorize", QUERY);

    private static final String FINAL_LOGIN_EXPECTED_URL = String.format("**/oauth2/authorize?%s&continue", QUERY);
    private static final String FINAL_EXPECTED_URL = "https://oauth.pstmn.io/v1/*";

    @Autowired
    private MockMvc mockMvc;

    @LocalServerPort
    private int port;

    @Test
    void test_nominal_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);
        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);
    }

    @Test
    void test_skip_login_process_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);
        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);

        sendInitialRequest(session, FINAL_EXPECTED_URL);
    }

    @Test
    void test_mfa_error_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);
        sendMfaRequest(session, "1", "/mfa?error");
        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);
    }

    @Test
    void test_question_error_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);
        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "no", "/question?error");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);
    }

    @Test
    void test_skip_by_get_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);

        // user is in mfa view and try to skip mfa process to go to question view
        mockMvc.perform(get(String.format("http://localhost:%s/question", port)).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(findBestMatcher("/mfa"));

        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);
    }

    @Test
    void test_skip_by_post_case() throws Exception {
        MockHttpSession session = new MockHttpSession();
        sendInitialRequest(session, "**/login");
        sendLoginRequest(session);

        // skip the mfa process
        sendQuestionRequest(session, "yes", "/mfa");

        sendMfaRequest(session, "1234", "**/question");
        sendQuestionRequest(session, "yes", FINAL_LOGIN_EXPECTED_URL);
    }

    private void sendInitialRequest(MockHttpSession session, String expectedUrl) throws Exception {
        mockMvc.perform(get(URL).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(findBestMatcher(expectedUrl));
    }

    private void sendLoginRequest(MockHttpSession session) throws Exception {
        mockMvc.perform(post(String.format("http://localhost:%s/login", port))
                        .session(session)
                        .with(csrf())
                        .param("username", "user")
                        .param("password", "user"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/mfa"));
    }

    private void sendMfaRequest(MockHttpSession session, String code, String expectedUrl) throws Exception {
        mockMvc.perform(post(String.format("http://localhost:%s/mfa", port))
                        .session(session)
                        .with(csrf())
                        .param("mfa_code", code))
                .andExpect(status().is3xxRedirection())
                .andExpect(findBestMatcher(expectedUrl));
    }

    private void sendQuestionRequest(MockHttpSession session, String answer, String expectedUrl) throws Exception {
        mockMvc.perform(post(String.format("http://localhost:%s/question", port))
                        .session(session)
                        .with(csrf())
                        .param("answer", answer))
                .andExpect(status().is3xxRedirection())
                .andExpect(findBestMatcher(expectedUrl));
    }

    private ResultMatcher findBestMatcher(String expectedUrl) {
        if (expectedUrl.contains("*")) {
            return redirectedUrlPattern(expectedUrl);
        }

        return redirectedUrl(expectedUrl);
    }
}
