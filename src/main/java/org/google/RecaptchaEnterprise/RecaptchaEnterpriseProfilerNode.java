/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.google.RecaptchaEnterprise;

import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_ACTION;
import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_SITE_KEY;
import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_TOKEN;

import java.util.Arrays;

import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that instruments the ForgeRock Login page with reCaptcha Enterprise
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = RecaptchaEnterpriseProfilerNode.Config.class)
public class RecaptchaEnterpriseProfilerNode extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger(RecaptchaEnterpriseProfilerNode.class);
    private final Config config;


    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * reCaptcha Enterprise Site Key
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String siteKey();

        /**
         * reCaptcha Enterprise Action
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        default String action() {return "LOGIN";}


    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public RecaptchaEnterpriseProfilerNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;

        if (context.hasCallbacks() && context.getCallback(TextOutputCallback.class).isPresent() && context.getCallback(
                HiddenValueCallback.class).isPresent()) {
            String token = context.getCallback(HiddenValueCallback.class).get().getValue();
            logger.debug("reCaptcha Callbacks Received, token is: {}", token);
            sharedState.put(RECAPTCHA_TOKEN, token);
            sharedState.put(RECAPTCHA_SITE_KEY, config.siteKey());
            sharedState.put(RECAPTCHA_ACTION, config.action());
            return goToNext().replaceSharedState(sharedState).build();
        }

        String script = String.format(RecaptchaHelper.SETUP_DOM_SCRIPT, config.siteKey(), config.action());
        return Action.send(
                Arrays.asList(new HiddenValueCallback(RECAPTCHA_TOKEN), new ScriptTextOutputCallback(script))).build();
    }
}
