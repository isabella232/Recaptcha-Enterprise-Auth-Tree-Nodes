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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.google.cloud.recaptchaenterprise.v1beta1.RecaptchaEnterpriseServiceV1Beta1Client;

import com.google.recaptchaenterprise.v1beta1.AnnotateAssessmentRequest;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.cloud.recaptchaenterprise.v1.RecaptchaEnterpriseServiceClient;
import com.google.inject.assistedinject.Assisted;
import com.google.recaptchaenterprise.v1.Assessment;
import com.google.recaptchaenterprise.v1.Event;
import com.google.recaptchaenterprise.v1.ProjectName;
import com.google.recaptchaenterprise.v1.RiskAnalysis;
import com.sun.identity.sm.RequiredValueValidator;

import static org.google.RecaptchaEnterprise.RecaptchaHelper.*;

/**
 * A node that instruments the ForgeRock Login page with reCaptcha Enterprise
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = RecaptchaEnterpriseAssessmentNode.Config.class)
public class RecaptchaEnterpriseAssessmentNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(RecaptchaEnterpriseProfilerNode.class);
    private final Config config;


    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * reCaptcha Enterprise Project ID
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String projectId();

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
    public RecaptchaEnterpriseAssessmentNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;

        RecaptchaEnterpriseServiceClient recaptchaEnterpriseServiceClient = getRecaptchaEnterpriseServiceClient(
                config.key());

        Assessment assessment = Assessment.newBuilder().setEvent(Event.newBuilder().setToken(
                        sharedState.get(RECAPTCHA_TOKEN).asString()).setSiteKey(sharedState.get(RECAPTCHA_SITE_KEY).asString())
                .build()).build();
        Assessment response = recaptchaEnterpriseServiceClient.createAssessment(ProjectName.of(config.projectId()),
                assessment);
        recaptchaEnterpriseServiceClient.close();
        if (!response.getTokenProperties().getValid()) {
            logger.error("Recaptcha Token is note valid");
            return goTo(false).replaceSharedState(sharedState).build();
        }
        RiskAnalysis analysis = response.getRiskAnalysis();

        List<RiskAnalysis.ClassificationReason> reasons = new ArrayList<>(analysis.getReasonsList());
        List<String> stringReasons = new ArrayList<>();
        reasons.forEach(reason -> stringReasons.add(reason.name()));
        sharedState.put(RECAPTCHA_SCORE, analysis.getScore());
        sharedState.put(RECAPTCHA_REASON_CODE_LIST, stringReasons);
        sharedState.put(RECAPTCHA_ASSESSMENT_NAME, response.getName());

        try {
            String token = context.getCallback(HiddenValueCallback.class).get().getValue();
            RecaptchaEnterpriseServiceV1Beta1Client recaptchaEnterpriseServiceClient2 = getRecaptchaEnterpriseServiceClientBeta(
                    config.key());
            com.google.recaptchaenterprise.v1beta1.Assessment assessment2 = com.google.recaptchaenterprise.v1beta1.Assessment.newBuilder().setEvent(com.google.recaptchaenterprise.v1beta1.Event.newBuilder().setToken(token).setSiteKey(sharedState.get(RECAPTCHA_SITE_KEY).asString()).build()).build();
            com.google.recaptchaenterprise.v1beta1.Assessment response2 = recaptchaEnterpriseServiceClient2.createAssessment(String.valueOf(ProjectName.of(config.projectId())),
                    assessment2);
            recaptchaEnterpriseServiceClient2.close();
            sharedState.put("riskScore", response2.getScore());
        }
        catch (Exception e) {
            e.printStackTrace();
        }



        return goTo(true).replaceSharedState(sharedState).build();
    }

    public static Integer getRiskScore() {



        //        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create(""))
//                .setHeader("Authorization", "")
//                .method("POST", HttpRequest.BodyPublishers.noBody())
//                .build();
//        HttpResponse<String> response = null;
//        try {
//            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//        System.out.println(response.body());
//
//        JSONObject obj = new JSONObject(response.body());
//        String riskScore = obj.getString("score");

        return 1;
    }

}
