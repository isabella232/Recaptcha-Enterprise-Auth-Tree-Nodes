package org.google.RecaptchaEnterprise;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceClient;
import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceSettings;

final class RecaptchaHelper {
    static final String RECAPTCHA_TOKEN = "recaptcha_token";
    static final String RECAPTCHA_SITE_KEY = "recaptcha_site_key";
    static final String RECAPTCHA_ACTION = "recaptcha_action";
    static final String RECAPTCHA_SCORE = "recaptcha_score";
    static final String RECAPTCHA_REASON_CODE_LIST = "recaptcha_reason_code_list";
    static final String RECAPTCHA_ASSESSMENT_NAME = "recaptcha_assessment_name";
    static final String SETUP_DOM_SCRIPT =
            "var script = document.createElement('script');\n" +
                    "script.src = 'https://www.google.com/recaptcha/enterprise" +
                    ".js?render=%1$s';\n" +
                    "script.onload = function () {grecaptcha.enterprise.ready(function() {grecaptcha.enterprise" +
                    ".execute('%1$s', {action: '%2$s'}).then(function(token) " +
                    "{document.getElementById('recaptcha_token').setAttribute('value', token); })" +
                    ";});};\n" +
                    "document.body.appendChild(script);\n";
    private static final Logger logger = LoggerFactory.getLogger(RecaptchaHelper.class);

    static RecaptchaEnterpriseServiceClient getRecaptchaEnterpriseServiceClient(char[] key)
            throws NodeProcessException {
        RecaptchaEnterpriseServiceClient recaptchaEnterpriseServiceClient;
        try {
            ServiceAccountCredentials credentials = ServiceAccountCredentials.fromStream(
                    new ByteArrayInputStream(new String(key).getBytes()));

            RecaptchaEnterpriseServiceSettings
                    recaptchaEnterpriseServiceSettings =
                    RecaptchaEnterpriseServiceSettings.newBuilder().setCredentialsProvider(
                            FixedCredentialsProvider.create(credentials)).build();
            recaptchaEnterpriseServiceClient = RecaptchaEnterpriseServiceClient.create(
                    recaptchaEnterpriseServiceSettings);
        } catch (IOException e) {
            logger.error("Unable to create Recaptcha Enterprise client");
            logger.error(e.getMessage());
            throw new NodeProcessException(e);
        }
        return recaptchaEnterpriseServiceClient;
    }
}
