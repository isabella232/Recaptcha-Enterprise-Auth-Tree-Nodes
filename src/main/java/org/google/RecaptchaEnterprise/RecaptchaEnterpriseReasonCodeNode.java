package org.google.RecaptchaEnterprise;

import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_REASON_CODE_LIST;
import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_SCORE;

import java.util.Collection;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import com.google.common.collect.ImmutableMap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.google.recaptchaenterprise.v1.RiskAnalysis;

/**
 * A node that checks Recaptcha Enterprise Reason Codes
 */
@Node.Metadata(outcomeProvider = RecaptchaEnterpriseReasonCodeNode.RecaptchaEnterpriseReasonCodeOutcomeProvider.class,
        configClass = RecaptchaEnterpriseReasonCodeNode.Config.class, tags = {"risk"})
public class RecaptchaEnterpriseReasonCodeNode implements Node {

    private static final String BUNDLE = RecaptchaEnterpriseReasonCodeNode.class.getName();
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public RecaptchaEnterpriseReasonCodeNode(@Assisted Config config) {
        this.config = config;
    }


    @Override
    public Action process(TreeContext context) {

        Collection<String> reasonCodes = context.sharedState.get(RECAPTCHA_REASON_CODE_LIST).asCollection(
                String.class);

        if (reasonCodes.contains(RiskAnalysis.ClassificationReason.AUTOMATION.name())) {
            reasonCodes.remove(RiskAnalysis.ClassificationReason.AUTOMATION.name());
            return goTo(RecaptchaReasonCodeOutcome.AUTOMATION.name()).replaceSharedState(
                    context.sharedState.put(RECAPTCHA_REASON_CODE_LIST, reasonCodes)).build();
        }
        if (reasonCodes.contains(RiskAnalysis.ClassificationReason.UNEXPECTED_ENVIRONMENT.name())) {
            reasonCodes.remove(RiskAnalysis.ClassificationReason.UNEXPECTED_ENVIRONMENT.name());
            return goTo(RecaptchaReasonCodeOutcome.UNEXPECTED_ENVIRONMENT.name()).replaceSharedState(
                    context.sharedState.put(RECAPTCHA_REASON_CODE_LIST, reasonCodes)).build();
        }
        if (reasonCodes.contains(RiskAnalysis.ClassificationReason.TOO_MUCH_TRAFFIC.name())) {
            reasonCodes.remove(RiskAnalysis.ClassificationReason.TOO_MUCH_TRAFFIC.name());
            return goTo(RecaptchaReasonCodeOutcome.TOO_MUCH_TRAFFIC.name()).replaceSharedState(
                    context.sharedState.put(RECAPTCHA_REASON_CODE_LIST, reasonCodes)).build();
        }
        if (reasonCodes.contains(RiskAnalysis.ClassificationReason.UNEXPECTED_USAGE_PATTERNS.name())) {
            reasonCodes.remove(RiskAnalysis.ClassificationReason.UNEXPECTED_USAGE_PATTERNS.name());
            return goTo(RecaptchaReasonCodeOutcome.UNEXPECTED_USAGE_PATTERNS.name()).replaceSharedState(
                    context.sharedState.put(RECAPTCHA_REASON_CODE_LIST, reasonCodes)).build();
        }
        if (reasonCodes.contains(RiskAnalysis.ClassificationReason.LOW_CONFIDENCE_SCORE.name())) {
            reasonCodes.remove(RiskAnalysis.ClassificationReason.LOW_CONFIDENCE_SCORE.name());
            return goTo(RecaptchaReasonCodeOutcome.LOW_CONFIDENCE_SCORE.name()).replaceSharedState(
                    context.sharedState.put(RECAPTCHA_REASON_CODE_LIST, reasonCodes)).build();
        }
        return goTo(RecaptchaReasonCodeOutcome.NONE.name()).build();
    }


    /**
     * The possible outcomes for the RecaptchaEnterpriseReasonCodeNode.
     */
    public enum RecaptchaReasonCodeOutcome {
        /**
         * The interaction matches the behavior of an automated agent.
         */
        AUTOMATION,
        /**
         * The event originated from an illegitimate environment.
         */
        UNEXPECTED_ENVIRONMENT,
        /**
         * Traffic volume from the event source is higher than normal.
         */
        TOO_MUCH_TRAFFIC,
        /**
         * The interaction with your site was significantly different from expected patterns.
         */
        UNEXPECTED_USAGE_PATTERNS,
        /**
         * Too little traffic has been received from this site thus far to generate quality risk analysis.
         */
        LOW_CONFIDENCE_SCORE,
        /**
         * No Reason Codes Returned
         */
        NONE

    }


    /**
     * Defines the possible outcomes from this Recaptcha node.
     */
    public static class RecaptchaEnterpriseReasonCodeOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(RecaptchaEnterpriseReasonCodeNode.BUNDLE,
                                                                       RecaptchaEnterpriseReasonCodeOutcomeProvider.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(RecaptchaReasonCodeOutcome.AUTOMATION.name(), bundle.getString("automationOutcome")),
                    new Outcome(RecaptchaReasonCodeOutcome.UNEXPECTED_ENVIRONMENT.name(),
                                bundle.getString("unexpectedEnvironmentOutcome")),
                    new Outcome(RecaptchaReasonCodeOutcome.TOO_MUCH_TRAFFIC.name(),
                                bundle.getString("tooMuchTrafficOutcome")),
                    new Outcome(RecaptchaReasonCodeOutcome.UNEXPECTED_USAGE_PATTERNS.name(),
                                bundle.getString("unexpectedUsagePatternsOutcome")),
                    new Outcome(RecaptchaReasonCodeOutcome.LOW_CONFIDENCE_SCORE.name(),
                                bundle.getString("lowConfidenceScoreOutcome")),
                    new Outcome(RecaptchaReasonCodeOutcome.NONE.name(), bundle.getString("noneOutcome")));
        }
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[] {new InputState(RECAPTCHA_REASON_CODE_LIST, true)};
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(RECAPTCHA_REASON_CODE_LIST, ImmutableMap.of("outcome", true))};
    }
}
