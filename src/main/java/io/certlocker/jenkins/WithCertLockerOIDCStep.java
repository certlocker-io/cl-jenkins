/*
 * Environment binding and console filtering adapted from Jenkins credentials-binding
 * BindingStep.java (https://github.com/jenkinsci/credentials-binding-plugin).
 *
 * MIT License
 *
 * Copyright 2015 Jesse Glick.
 * Copyright (c) 2026 CertLocker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package io.certlocker.jenkins;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;
import org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback;
import org.jenkinsci.plugins.workflow.steps.BodyInvoker;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/** Exchanges a signed build identity and scopes the resulting token to its Pipeline body. */
public final class WithCertLockerOIDCStep extends Step {
    private final String server;
    private String tokenType = "SECRET";

    @DataBoundConstructor
    public WithCertLockerOIDCStep(String server) {
        this.server = server;
    }

    public String getServer() {
        return server;
    }

    public String getTokenType() {
        return tokenType;
    }

    @DataBoundSetter
    public void setTokenType(String tokenType) {
        if (!ExchangeClient.TOKEN_TYPES.contains(tokenType)) {
            throw new IllegalArgumentException("tokenType must be SECRET, CERTIFICATE or MCP");
        }
        this.tokenType = tokenType;
    }

    @Override
    public StepExecution start(StepContext context) {
        return new Execution(this, context);
    }

    private static final class Execution extends GeneralNonBlockingStepExecution {
        private static final long serialVersionUID = 1L;
        private final String server;
        private final String tokenType;

        Execution(WithCertLockerOIDCStep step, StepContext context) {
            super(context);
            server = step.server;
            tokenType = step.tokenType;
        }

        @Override
        public boolean start() {
            run(this::open);
            return false;
        }

        private void open() throws Exception {
            Run<?, ?> build = getContext().get(Run.class);
            CertLockerServer profile = CertLockerConfiguration.get().findServer(server);
            if (profile == null) {
                throw new AbortException("Unknown CertLocker server; ask your Jenkins administrator to configure it");
            }
            BuildIdentity.Identity identity = BuildIdentity.exchange(profile, build, tokenType);
            String jwt = identity.jwt();
            String token = identity.token();
            getContext()
                    .newBodyInvoker()
                    .withContext(EnvironmentExpander.merge(
                            getContext().get(EnvironmentExpander.class), new TokenEnvironment(token, profile.getUrl())))
                    .withContext(BodyInvoker.mergeConsoleLogFilters(
                            getContext().get(ConsoleLogFilter.class),
                            new TokenFilter(
                                    List.of(token, jwt), build.getCharset().name())))
                    .withCallback(BodyExecutionCallback.wrap(getContext()))
                    .start();
        }
    }

    static final class TokenEnvironment extends EnvironmentExpander {
        private static final long serialVersionUID = 1L;
        private final Secret token;
        private final String url;

        TokenEnvironment(String token, String url) {
            this.token = Secret.fromString(token);
            this.url = url;
        }

        @Override
        public void expand(EnvVars env) {
            env.override("TRUST_API_TOKEN", token.getPlainText());
            env.override("TRUST_URL", url);
        }

        @NonNull
        @Override
        public Set<String> getSensitiveVariables() {
            return Set.of("TRUST_API_TOKEN");
        }
    }

    static final class TokenFilter extends ConsoleLogFilter implements Serializable {
        private static final long serialVersionUID = 1L;
        private final Secret pattern;
        private final String charset;

        TokenFilter(List<String> secrets, String charset) {
            pattern = Secret.fromString(
                    SecretPatterns.getAggregateSecretPattern(secrets).pattern());
            this.charset = charset;
        }

        @Override
        public OutputStream decorateLogger(AbstractBuild build, OutputStream out) throws IOException {
            return new SecretPatterns.MaskingOutputStream(out, () -> Pattern.compile(pattern.getPlainText()), charset);
        }
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {
        public hudson.util.ListBoxModel doFillServerItems() {
            return StepUi.servers();
        }

        public hudson.util.ListBoxModel doFillTokenTypeItems() {
            var items = new hudson.util.ListBoxModel();
            for (String type : List.of("SECRET", "CERTIFICATE", "MCP")) {
                items.add(type, type);
            }
            return items;
        }

        @Override
        public String getFunctionName() {
            return "withCertLockerOIDC";
        }

        @Override
        public String getDisplayName() {
            return "Use a CertLocker token issued for this Jenkins build";
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of(Run.class, TaskListener.class);
        }
    }
}
