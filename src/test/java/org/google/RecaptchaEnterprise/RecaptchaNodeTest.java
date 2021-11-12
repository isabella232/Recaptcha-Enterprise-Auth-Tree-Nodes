package org.google.RecaptchaEnterprise;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.json.JSONException;
import org.junit.jupiter.api.Test;

class RecaptchaNodeTest {

    @Test
    void checkRiskScoreSafeTest() throws JSONException {
        Integer riskScore = RecaptchaEnterpriseAssessmentNode.getRiskScore();
        assertTrue(riskScore == 0);
    }


}