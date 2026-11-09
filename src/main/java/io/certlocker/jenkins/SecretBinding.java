package io.certlocker.jenkins;

import hudson.AbortException;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import net.sf.json.JSONArray;
import net.sf.json.JSONNull;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/** A source reference and binding options only; never stores fetched secret values. */
public final class SecretBinding extends AbstractDescribableImpl<SecretBinding> implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String secretId;
    private final String variable;
    private String mode = "ENV";
    private String field;
    private String fileName;
    private boolean base64;
    private static final Set<String> RESERVED = Set.of(
            "PATH",
            "HOME",
            "SHELL",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "TRUST_API_TOKEN",
            "TRUST_URL");

    @DataBoundConstructor
    public SecretBinding(String secretId, String variable) {
        this.secretId = pathId(secretId);
        if (variable == null || !variable.matches("[A-Za-z_][A-Za-z0-9_]*") || RESERVED.contains(variable)) {
            throw new IllegalArgumentException(
                    "Secret variable must be a valid, non-reserved environment variable name");
        }
        this.variable = variable;
    }

    static String pathId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,255}")) {
            throw new IllegalArgumentException(
                    "Account and secret IDs must use letters, digits, dash, underscore or dot");
        }
        return value;
    }

    public String getSecretId() {
        return secretId;
    }

    public String getVariable() {
        return variable;
    }

    public String getMode() {
        return mode;
    }

    public String getField() {
        return field;
    }

    public String getFileName() {
        return fileName;
    }

    public boolean isBase64() {
        return base64;
    }

    @DataBoundSetter
    public void setMode(String mode) {
        if (!"ENV".equals(mode) && !"FILE".equals(mode)) {
            throw new IllegalArgumentException("Secret mode must be ENV or FILE");
        }
        this.mode = mode;
    }

    @DataBoundSetter
    public void setField(String field) {
        if (field != null && field.length() > 1024) {
            throw new IllegalArgumentException("Secret field selector is too long");
        }
        this.field = field == null || field.isEmpty() ? null : field;
    }

    @DataBoundSetter
    public void setFileName(String fileName) {
        if (fileName != null && fileName.isEmpty()) {
            fileName = null;
        }
        if (fileName != null
                && (!fileName.matches("[A-Za-z0-9_.-]{1,128}") || fileName.equals(".") || fileName.equals(".."))) {
            throw new IllegalArgumentException("Secret file name must be a plain file name, without directories");
        }
        this.fileName = fileName;
    }

    @DataBoundSetter
    public void setBase64(boolean base64) {
        this.base64 = base64;
    }

    byte[] select(byte[] raw) throws IOException {
        byte[] result = raw;
        if (field != null) {
            try {
                JSONObject objectRoot = JSONObject.fromObject(utf8(raw));
                Object value = objectRoot;
                if (field.startsWith("/")) {
                    for (String part : field.substring(1).split("/", -1)) {
                        if (part.matches(".*~(?:[^01]|$).*")) {
                            throw new IllegalArgumentException();
                        }
                        String key = part.replace("~1", "/").replace("~0", "~");
                        if (value instanceof JSONObject object && object.containsKey(key)) {
                            value = object.get(key);
                        } else if (value instanceof JSONArray array && key.matches("0|[1-9][0-9]*")) {
                            value = array.get(Integer.parseInt(key));
                        } else {
                            throw new IllegalArgumentException();
                        }
                    }
                } else if (objectRoot.containsKey(field)) {
                    value = objectRoot.get(field);
                } else {
                    throw new IllegalArgumentException();
                }
                if (value == null
                        || value instanceof JSONNull
                        || value instanceof JSONObject
                        || value instanceof JSONArray) {
                    throw new IllegalArgumentException();
                }
                result = value.toString().getBytes(StandardCharsets.UTF_8);
            } catch (RuntimeException | CharacterCodingException e) {
                throw new AbortException(
                        "Secret field is missing, null, non-scalar or not valid JSON (binding " + variable + ")");
            }
        }
        if (base64) {
            try {
                result = Base64.getDecoder().decode(utf8(result).replaceAll("\\s", ""));
            } catch (IllegalArgumentException | CharacterCodingException e) {
                throw new AbortException("Secret is not valid Base64 (binding " + variable + ")");
            }
        }
        if (mode.equals("ENV")) {
            try {
                String text = utf8(result);
                if (text.indexOf('\0') >= 0 || result.length > 65536) {
                    throw new IllegalArgumentException();
                }
            } catch (IllegalArgumentException | CharacterCodingException e) {
                throw new AbortException(
                        "Secret cannot be an environment value; use mode FILE for binary or large contents (binding "
                                + variable + ")");
            }
        }
        return result;
    }

    static String utf8(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecretBinding> {
        public hudson.util.ListBoxModel doFillModeItems() {
            var items = new hudson.util.ListBoxModel();
            items.add("Environment variable", "ENV");
            items.add("Temporary file path", "FILE");
            return items;
        }

        @Override
        public String getDisplayName() {
            return "Trust secret binding";
        }
    }
}
