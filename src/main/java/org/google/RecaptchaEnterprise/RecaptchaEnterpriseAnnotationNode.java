package org.google.RecaptchaEnterprise;

import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_ASSESSMENT_NAME;
import static org.google.RecaptchaEnterprise.RecaptchaHelper.getRecaptchaEnterpriseServiceClient;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceClient;
import com.google.inject.assistedinject.Assisted;
import com.google.recaptchaenterprise.v1.AnnotateAssessmentRequest;
import com.sun.identity.sm.RequiredValueValidator;


/**
 * A node that annotates recaptcha enterprise assessments.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = RecaptchaEnterpriseAnnotationNode.Config.class)
public class RecaptchaEnterpriseAnnotationNode extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger(RecaptchaEnterpriseAnnotationNode.class);
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Annotation Configuration
         */
        @Attribute(order = 100)
        default AnnotateAssessmentRequest.Annotation annotation() { return AnnotateAssessmentRequest.Annotation.LEGITIMATE; }

        /**
         * reCaptcha Enterprise Key
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        @Password
        char[] key();

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public RecaptchaEnterpriseAnnotationNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        try (RecaptchaEnterpriseServiceClient recaptchaEnterpriseServiceClient = getRecaptchaEnterpriseServiceClient(
                config.key())) {
            recaptchaEnterpriseServiceClient.annotateAssessment(AnnotateAssessmentRequest.newBuilder().setAnnotation(
                    config.annotation()).setName(context.sharedState.get(RECAPTCHA_ASSESSMENT_NAME).asString())
                                                                                         .build());
            if (logger.isDebugEnabled()) {
                logger.debug("Annotated assessment {} with value {}",
                             context.sharedState.get(RECAPTCHA_ASSESSMENT_NAME).asString(),
                             config.annotation().toString());
            }

        }
        return goToNext().build();
    }

}
