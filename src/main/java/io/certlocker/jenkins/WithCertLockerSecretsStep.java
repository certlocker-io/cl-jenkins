package io.certlocker.jenkins;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jenkins.agents.ControllerToAgentFileCallable;
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

/** Authenticates once, fetches each secret once, then binds requested values for the body. */
public final class WithCertLockerSecretsStep extends Step {
    private final String server;
    private final List<SecretBinding> secrets;
    private String account;

    @DataBoundConstructor
    public WithCertLockerSecretsStep(String server, List<SecretBinding> secrets) {
        if (secrets == null || secrets.isEmpty() || secrets.size() > 32) {
            throw new IllegalArgumentException("Request between 1 and 32 Trust secret bindings");
        }
        var variables = new HashSet<String>();
        for (var binding : secrets) {
            if (binding == null || !variables.add(binding.getVariable())) {
                throw new IllegalArgumentException("Trust secret binding variables must be unique");
            }
        }
        this.server = server;
        this.secrets = List.copyOf(secrets);
    }

    public String getServer() {
        return server;
    }

    public List<SecretBinding> getSecrets() {
        return secrets;
    }

    public String getAccount() {
        return account;
    }

    @DataBoundSetter
    public void setAccount(String account) {
        this.account = account == null || account.isBlank() ? null : SecretBinding.pathId(account);
    }

    @Override
    public StepExecution start(StepContext context) {
        return new Execution(this, context);
    }

    private static final class Execution extends GeneralNonBlockingStepExecution {
        private static final long serialVersionUID = 1L;
        private final String server;
        private final String account;
        private final List<SecretBinding> bindings;

        Execution(WithCertLockerSecretsStep step, StepContext context) {
            super(context);
            server = step.server;
            account = step.account;
            bindings = step.secrets;
        }

        @Override
        public boolean start() {
            run(this::open);
            return false;
        }

        private void open() throws Exception {
            CertLockerServer profile = CertLockerConfiguration.get().findServer(server);
            if (profile == null) {
                throw new AbortException("Unknown CertLocker server; ask your Jenkins administrator to configure it");
            }
            String targetAccount = account != null ? account : profile.getAccount();
            if (targetAccount == null) {
                throw new AbortException(
                        "Set account on withCertLockerSecrets or configure the server's default account");
            }
            boolean needsFiles = bindings.stream().anyMatch(b -> b.getMode().equals("FILE"));
            FilePath workspace = needsFiles ? getContext().get(FilePath.class) : null;
            if (needsFiles && workspace == null) {
                throw new AbortException("Trust FILE bindings require a node/agent block");
            }
            Run<?, ?> build = getContext().get(Run.class);
            var identity = BuildIdentity.exchange(profile, build, "SECRET");
            var masks = new ArrayList<String>();
            masks.add(identity.jwt());
            masks.add(identity.token());
            Map<String, byte[]> fetched = new HashMap<>();
            Map<SecretBinding, byte[]> selected = new LinkedHashMap<>();
            int total = 0;
            for (var binding : bindings) {
                byte[] bytes = fetched.get(binding.getSecretId());
                if (bytes == null) {
                    try {
                        bytes = new TrustSecretClient()
                                .fetch(profile, targetAccount, binding.getSecretId(), identity.token());
                    } catch (AbortException e) {
                        throw new AbortException("Trust binding " + binding.getVariable() + ": " + e.getMessage());
                    }
                    total += bytes.length;
                    if (total > 16 * 1024 * 1024) {
                        throw new AbortException("Trust bindings exceed the 16 MiB combined fetch limit");
                    }
                    fetched.put(binding.getSecretId(), bytes);
                    addMasks(masks, bytes);
                }
                byte[] value = binding.select(bytes);
                selected.put(binding, value);
                addMasks(masks, value);
            }
            String directory = null;
            try {
                if (needsFiles) {
                    directory = workspace.act(new CreateDirectory());
                }
                Map<String, String> values = new LinkedHashMap<>();
                for (var entry : selected.entrySet()) {
                    var binding = entry.getKey();
                    if (binding.getMode().equals("ENV")) {
                        values.put(binding.getVariable(), SecretBinding.utf8(entry.getValue()));
                    } else {
                        FilePath folder = new FilePath(workspace.getChannel(), directory).child(binding.getVariable());
                        folder.mkdirs();
                        folder.chmod(0700);
                        FilePath file = folder.child(binding.getFileName() == null ? "secret" : binding.getFileName());
                        try (var out = file.write()) {
                            out.write(entry.getValue());
                        }
                        file.chmod(0600);
                        values.put(binding.getVariable(), file.getRemote());
                    }
                }
                getContext()
                        .newBodyInvoker()
                        .withContext(EnvironmentExpander.merge(
                                getContext().get(EnvironmentExpander.class), new BoundEnvironment(values)))
                        .withContext(BodyInvoker.mergeConsoleLogFilters(
                                getContext().get(ConsoleLogFilter.class),
                                new WithCertLockerOIDCStep.TokenFilter(
                                        masks, build.getCharset().name())))
                        .withCallback(new Cleanup(directory))
                        .start();
            } catch (IOException | InterruptedException | RuntimeException e) {
                if (directory != null) {
                    try {
                        new FilePath(workspace.getChannel(), directory).deleteRecursive();
                    } catch (IOException | InterruptedException | RuntimeException cleanup) {
                        if (cleanup instanceof InterruptedException) {
                            Thread.currentThread().interrupt();
                        }
                        e.addSuppressed(cleanup);
                    }
                }
                throw e;
            }
        }
    }

    private static void addMasks(List<String> masks, byte[] bytes) {
        try {
            String text = SecretBinding.utf8(bytes);
            if (!text.isEmpty()) {
                masks.add(text);
                text.lines().filter(line -> line.length() >= 3).forEach(masks::add);
            }
        } catch (java.nio.charset.CharacterCodingException ignored) {
            // Binary file bytes have no reliable console representation. Never log them.
        }
    }

    private static final class CreateDirectory implements ControllerToAgentFileCallable<String> {
        private static final long serialVersionUID = 1L;

        @Override
        public String invoke(File ignored, VirtualChannel channel) throws IOException {
            // System temp is outside browsable workspaces, including nested dir() blocks.
            return Files.createTempDirectory("certlocker-secrets-")
                    .toAbsolutePath()
                    .toString();
        }
    }

    static final class BoundEnvironment extends EnvironmentExpander {
        private static final long serialVersionUID = 1L;
        private final Map<String, Secret> values = new LinkedHashMap<>();

        BoundEnvironment(Map<String, String> values) {
            values.forEach((k, v) -> this.values.put(k, Secret.fromString(v)));
        }

        @Override
        public void expand(EnvVars env) {
            values.forEach((k, v) -> env.override(k, v.getPlainText()));
        }

        @NonNull
        @Override
        public Set<String> getSensitiveVariables() {
            return Set.copyOf(values.keySet());
        }
    }

    private static final class Cleanup extends BodyExecutionCallback.TailCall {
        private static final long serialVersionUID = 1L;
        private final String directory;

        Cleanup(String directory) {
            this.directory = directory;
        }

        @Override
        protected void finished(StepContext context) throws Exception {
            if (directory != null) {
                FilePath workspace = context.get(FilePath.class);
                if (workspace == null) {
                    throw new AbortException("Unable to clean up Trust secret files: agent workspace unavailable");
                }
                new FilePath(workspace.getChannel(), directory).deleteRecursive();
            }
        }
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {
        @Override
        public String getFunctionName() {
            return "withCertLockerSecrets";
        }

        @Override
        public String getDisplayName() {
            return "Bind Trust secrets as masked variables or private files";
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of(Run.class, TaskListener.class);
        }

        public ListBoxModel doFillServerItems() {
            return StepUi.servers();
        }
    }
}
