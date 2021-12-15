package org.google.RecaptchaEnterprise;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.json.JSONException;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;

class RecaptchaNodeTest {

    @Test
    void checkRiskScoreSafeTest() throws JSONException, IOException, URISyntaxException, InterruptedException {
        Integer riskScore;
        riskScore = RecaptchaEnterpriseAssessmentNode.getPasswordLeakScore(System.getProperty("projectId"), System.getProperty("username"), "test");
        assertTrue(riskScore == 0);
    }


}