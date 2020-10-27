<!--
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
 * Copyright 2019 ForgeRock AS.
-->
# Recaptcha Enterprise Authentication Nodes

The Recaptcha Enterprise authentication nodes lets administrators integrate Recaptcha Enterprise decision tools into
 an AM authentication trees.

## Usage

To deploy these nodes, download the jar from the releases tab on github 
[here](https://github.com/ForgeRock/Recaptcha-Enterprise-Auth-Tree-Nodes/releases/latest). Next, copy the jar into
 the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed. Restart the web container to pick up the 
new nodes. The nodes will then appear in the authentication trees components palette.

This node assumes you have the following:
* A Google Cloud Project with reCaptcha Enterprise Enabled
* A reCAPTCHA Enterprise Key
    * That has the AM Domain whitelisted
    * That uses integration type: `Scoring, with no visible challenge to your users`


### Recaptcha Enterprise Profiler Node
This node tags the AM login page with the Recaptcha Enterprise JS to collect information about the event.

#### Recaptcha Enterprise Profiler Node Configuration
* **reCaptcha Enterprise Site Key** - Google reCaptcha Enterprise Site Key. You can find this key at <code>https
://console.cloud.google.com/recaptcha?project={{Project_ID}}</code>
* **reCaptcha Action** - The action that the user is performing when the instrumentation is performed.
  
### Recaptcha Enterprise Assessment Node
This node makes a request the Recaptcha Enterprise Assessment API to retrieve a score and reason codes about the
 users event.
 
#### Recaptcha Enterprise Assessment Node Configuration

 * **reCaptcha Enterprise Project Id** - Google Cloud Project Id
 * **Key** - Recaptcha Enterprise Service Account Key. Copy the entire JSON blob that was downloaded from the
  reCaptcha Enterprise servce into this field. An example of the key would be:
```json
{
  "type": "service_account",
  "project_id": "recaptcha-project-id",
  "private_key_id": "12903109239012903",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBAD...=\n-----END PRIVATE KEY-----\n",
  "client_email": "project@recaptcha-enterprise-12312.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/project%40name.iam.gserviceaccount.com"
}

```
 
### Recaptcha Enterprise Reason Code Node
This node analyzes the response from the Recaptcha Enterprise Assessment Node and routes to the first outcome
returned and removes it from the list. The possible outcomes are <code>Automation</code>, <code>Unexpected
Environment</code>, <code>Too Much Traffic</code>, <code>Unexpected Usage Patterns</code>, <code>Low Confidence
Score</code>, and <code>None Returned</code>. The Recaptcha Enterprise Reason Code Node can also be daisy-chained
together to test for a combination of outcomes.

### Recaptcha Enterprise Score Node
This node analyzes the response from the Recaptcha Enterprise Assessment Node and checks to see if the risk score
greater than or less than the configured value.

#### Recaptcha Enterprise Score Node

* **Score Threshold** - reCAPTCHA Enterprise returns a score (1.0 is very likely a good interaction, 0.0 is very
likely a bot). Based on the score, you can take appropriate action in the context of your site.

### Recaptcha Enterprise Annotation Node
This node calls the Recaptcha Enterprise Annotation API to tune your site specific model. This additional
information will help reCAPTCHA Enterprise perform better for your site over time.

#### Recaptcha Enterprise Annotation Node Configuration

* **Annotation** - The annotation to send for this assessment. The annotation options are <code>Unspecified</code>,
  <code>Legitimate</code>, <code>Fraudulent</code>, <code>Password Correct</code>, <code>Password Incorrect</code>,
   and <code>Unrecognized</code>.
 * **Key** - Recaptcha Enterprise Service Account Key. Copy the entire JSON blob that was downloaded from the
  reCaptcha Enterprise service into this field. This should be the same key used in the `Recaptcha Enterprise
   Assessment Node`. 

### Example Flow


![RECAPTCHA_TREE](./images/tree.png)