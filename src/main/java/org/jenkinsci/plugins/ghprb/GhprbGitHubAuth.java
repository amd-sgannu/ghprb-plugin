package org.jenkinsci.plugins.ghprb;

import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.google.common.base.Joiner;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.plaincredentials.FileCredentials;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.github.GHAuthorization;
import org.kohsuke.github.GHCommitState;
import org.kohsuke.github.GHIssue;
import org.kohsuke.github.GHMyself;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.verb.POST;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.Util.fixEmpty;
import static hudson.Util.fixEmptyAndTrim;

public class GhprbGitHubAuth extends AbstractDescribableImpl<GhprbGitHubAuth> {

    private static final Logger LOGGER = Logger.getLogger(GhprbGitHubAuth.class.getName());

    @Extension
    public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

    private static final int SHA1_PREFIX_LENGTH = 5;

    private static final int INITIAL_CAPACITY = 3;

    private final String serverAPIUrl;

    private final String jenkinsUrl;

    private final String credentialsId;

    private final String id;

    private final String description;

    private final Secret secret;

    private final String appId;

    private final String installationId;

    private transient GitHub gh;

    private transient GitHubAppTokenProvider tokenProvider;

    private transient String lastAppToken;

    @DataBoundConstructor
    public GhprbGitHubAuth(
            String serverAPIUrl,
            String jenkinsUrl,
            String credentialsId,
            String description,
            String id,
            Secret secret,
            String appId,
            String installationId
    ) {
        if (StringUtils.isEmpty(serverAPIUrl)) {
            serverAPIUrl = "https://api.github.com";
        }
        this.serverAPIUrl = fixEmptyAndTrim(serverAPIUrl);
        this.jenkinsUrl = fixEmptyAndTrim(jenkinsUrl);
        this.credentialsId = fixEmpty(credentialsId);
        if (StringUtils.isEmpty(id)) {
            id = UUID.randomUUID().toString();
        }

        this.id = IdCredentials.Helpers.fixEmptyId(id);
        this.description = description;
        this.secret = secret;
        this.appId = fixEmptyAndTrim(appId);
        this.installationId = fixEmptyAndTrim(installationId);
    }

    @Exported
    public String getServerAPIUrl() {
        return serverAPIUrl;
    }

    @Exported
    public String getJenkinsUrl() {
        return jenkinsUrl;
    }

    @Exported
    public String getCredentialsId() {
        return credentialsId;
    }

    @Exported
    public String getDescription() {
        return description;
    }

    @Exported
    public String getId() {
        return id;
    }


    @Exported
    public Secret getSecret() {
        return secret;
    }

    @Exported
    public String getAppId() {
        return appId;
    }

    @Exported
    public String getInstallationId() {
        return installationId;
    }

    private static final String GITHUB_APP_CREDENTIALS_CLASS =
            "org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials";

    private boolean isGitHubAppMode() {
        return !StringUtils.isEmpty(appId) && !StringUtils.isEmpty(installationId);
    }

    private boolean isGitHubAppCredential(StandardCredentials credentials) {
        return credentials != null
                && GITHUB_APP_CREDENTIALS_CLASS.equals(credentials.getClass().getName());
    }

    private GitHubAppTokenProvider getOrCreateTokenProvider(Item context) throws IOException {
        if (tokenProvider == null) {
            String pem = extractPemFromCredentials(context);
            try {
                tokenProvider = new GitHubAppTokenProvider(appId, installationId, pem, serverAPIUrl);
            } catch (java.security.GeneralSecurityException e) {
                throw new IOException("Failed to initialize GitHub App token provider", e);
            }
        }
        return tokenProvider;
    }

    private String extractPemFromCredentials(Item context) throws IOException {
        StandardCredentials credentials = Ghprb.lookupCredentials(context, credentialsId, serverAPIUrl);
        if (credentials == null) {
            throw new IOException("GitHub App credentials not found for id: " + credentialsId);
        }
        if (credentials instanceof StringCredentials) {
            return ((StringCredentials) credentials).getSecret().getPlainText();
        }
        if (credentials instanceof FileCredentials) {
            return readFileCredential((FileCredentials) credentials);
        }
        throw new IOException(
                "GitHub App requires Secret text or Secret file credential with PEM private key, got: "
                        + credentials.getClass().getName()
        );
    }

    private static String readFileCredential(FileCredentials fileCred) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(fileCred.getContent(), "UTF-8"));
        try {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(line);
            }
            return sb.toString();
        } finally {
            reader.close();
        }
    }

    /**
     * Gets a fresh installation token from a GitHubAppCredentials credential.
     * GitHubAppCredentials implements StandardUsernamePasswordCredentials;
     * its getPassword() returns a fresh installation access token.
     */
    private String getGitHubAppCredentialToken(Item context) throws IOException {
        StandardCredentials credentials = Ghprb.lookupCredentials(context, credentialsId, serverAPIUrl);
        if (credentials == null) {
            throw new IOException("GitHub App credentials not found for id: " + credentialsId);
        }
        if (credentials instanceof StandardUsernamePasswordCredentials) {
            return ((StandardUsernamePasswordCredentials) credentials).getPassword().getPlainText();
        }
        throw new IOException("Credential does not provide a password/token: "
                + credentials.getClass().getName());
    }

    public boolean checkSignature(String body, String signature) {
        if (secret == null || StringUtils.isEmpty(secret.getPlainText())) {
            return true;
        }

        if (signature != null && signature.startsWith("sha1=")) {
            String expected = signature.substring(SHA1_PREFIX_LENGTH);
            String algorithm = "HmacSHA1";
            try {
                SecretKeySpec keySpec = new SecretKeySpec(
                        secret.getPlainText().getBytes(Charset.forName("UTF-8")),
                        algorithm
                );
                Mac mac = Mac.getInstance(algorithm);
                mac.init(keySpec);
                byte[] localSignatureBytes = mac.doFinal(body.getBytes("UTF-8"));
                String localSignature = Hex.encodeHexString(localSignatureBytes);
                if (!localSignature.equals(expected)) {
                    LOGGER.log(Level.SEVERE, "Local signature {0} does not match external signature {1}",
                            new Object[] {localSignature, expected});
                    return false;
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Couldn't match both signatures");
                return false;
            }
        } else {
            LOGGER.log(
                    Level.SEVERE,
                    "Request doesn't contain a signature. "
                            + "Check that github has a secret that should be attached to the hook"
            );
            return false;
        }

        LOGGER.log(Level.INFO, "Signatures checking OK");
        return true;
    }

    private static GitHubBuilder getBuilder(Item context, String serverAPIUrl, String credentialsId) {
        return getBuilder(context, serverAPIUrl, credentialsId, null, null);
    }

    private static GitHubBuilder getBuilder(
            Item context, String serverAPIUrl, String credentialsId,
            String ghAppId, String ghInstallationId
    ) {
        GitHubBuilder builder = new GitHubBuilder()
                .withEndpoint(serverAPIUrl)
                .withConnector(new HttpConnectorWithJenkinsProxy());
        String contextName = context == null ? "(Jenkins.instance)" : context.getFullDisplayName();

        StandardCredentials credentials = StringUtils.isEmpty(credentialsId)
                ? null : Ghprb.lookupCredentials(context, credentialsId, serverAPIUrl);

        if (credentials != null
                && GITHUB_APP_CREDENTIALS_CLASS.equals(credentials.getClass().getName())) {
            LOGGER.log(Level.FINEST, "Using GitHubAppCredentials for context {0}", contextName);
            String token = ((StandardUsernamePasswordCredentials) credentials)
                    .getPassword().getPlainText();
            builder.withOAuthToken(token);
            return builder;
        }

        if (!StringUtils.isEmpty(ghAppId) && !StringUtils.isEmpty(ghInstallationId)) {
            LOGGER.log(Level.FINEST, "Using GitHub App auth for context {0} (App ID: {1})",
                    new Object[] {contextName, ghAppId});
            if (credentials == null) {
                LOGGER.log(Level.SEVERE,
                        "Failed to look up PEM credentials for GitHub App using id: {0}",
                        credentialsId);
                return null;
            }
            try {
                String pem = extractPemFromStatic(credentials);
                GitHubAppTokenProvider provider = new GitHubAppTokenProvider(
                        ghAppId, ghInstallationId, pem, serverAPIUrl);
                builder.withOAuthToken(provider.getToken());
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE,
                        "Failed to obtain GitHub App installation token for " + contextName, e);
                return null;
            }
            return builder;
        }

        if (StringUtils.isEmpty(credentialsId)) {
            LOGGER.log(Level.WARNING,
                    "credentialsId not set for context {0}, using anonymous connection",
                    contextName);
            return builder;
        }

        if (credentials == null) {
            LOGGER.log(Level.SEVERE, "Failed to look up credentials for context {0} using id: {1}",
                    new Object[] {contextName, credentialsId});
        } else if (credentials instanceof StandardUsernamePasswordCredentials) {
            LOGGER.log(Level.FINEST, "Using username/password for context {0}", contextName);
            StandardUsernamePasswordCredentials upCredentials =
                    (StandardUsernamePasswordCredentials) credentials;
            builder.withPassword(upCredentials.getUsername(),
                    upCredentials.getPassword().getPlainText());
        } else if (credentials instanceof StringCredentials) {
            LOGGER.log(Level.FINEST, "Using OAuth token for context {0}", contextName);
            StringCredentials tokenCredentials = (StringCredentials) credentials;
            builder.withOAuthToken(tokenCredentials.getSecret().getPlainText());
        } else {
            LOGGER.log(Level.SEVERE,
                    "Unknown credential type for context {0} using id: {1}: {2}",
                    new Object[] {contextName, credentialsId, credentials.getClass().getName()});
            return null;
        }
        return builder;
    }

    private static String extractPemFromStatic(StandardCredentials credentials) throws IOException {
        if (credentials instanceof StringCredentials) {
            return ((StringCredentials) credentials).getSecret().getPlainText();
        }
        if (credentials instanceof FileCredentials) {
            return readFileCredential((FileCredentials) credentials);
        }
        throw new IOException(
                "GitHub App requires Secret text or Secret file credential with PEM key, got: "
                        + credentials.getClass().getName()
        );
    }

    private void buildConnection(Item context) {
        GitHubBuilder builder = getBuilder(context, serverAPIUrl, credentialsId);
        if (builder == null) {
            LOGGER.log(Level.SEVERE, "Unable to get builder using credentials: {0}", credentialsId);
            return;
        }
        try {
            gh = builder.build();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Unable to connect using credentials: " + credentialsId, e);
        }
    }

    public GitHub getConnection(Item context) throws IOException {
        synchronized (this) {
            StandardCredentials credentials = StringUtils.isEmpty(credentialsId)
                    ? null : Ghprb.lookupCredentials(context, credentialsId, serverAPIUrl);

            if (isGitHubAppCredential(credentials)) {
                String token = getGitHubAppCredentialToken(context);
                if (gh == null || !token.equals(lastAppToken)) {
                    LOGGER.log(Level.INFO,
                            "[GHPRB-GitHubApp] Token changed, rebuilding GitHub API connection "
                                    + "(GitHubAppCredentials mode)");
                    gh = new GitHubBuilder()
                            .withEndpoint(serverAPIUrl)
                            .withConnector(new HttpConnectorWithJenkinsProxy())
                            .withOAuthToken(token)
                            .build();
                    lastAppToken = token;
                } else {
                    LOGGER.log(Level.INFO,
                            "[GHPRB-GitHubApp] Reusing existing GitHub API connection "
                                    + "(GitHubAppCredentials mode)");
                }
            } else if (isGitHubAppMode()) {
                GitHubAppTokenProvider provider = getOrCreateTokenProvider(context);
                String token = provider.getToken();
                if (gh == null || !token.equals(lastAppToken)) {
                    LOGGER.log(Level.INFO,
                            "[GHPRB-GitHubApp] Token changed, rebuilding GitHub API connection "
                                    + "(App ID: {0}, Installation: {1})",
                            new Object[] {appId, installationId});
                    gh = new GitHubBuilder()
                            .withEndpoint(serverAPIUrl)
                            .withConnector(new HttpConnectorWithJenkinsProxy())
                            .withOAuthToken(token)
                            .build();
                    lastAppToken = token;
                } else {
                    LOGGER.log(Level.INFO,
                            "[GHPRB-GitHubApp] Reusing existing GitHub API connection "
                                    + "(App ID: {0}, Installation: {1})",
                            new Object[] {appId, installationId});
                }
            } else {
                if (gh == null) {
                    buildConnection(context);
                }
            }
            return gh;
        }
    }

    /**
     * Invalidates the cached GitHub connection and any cached tokens,
     * forcing a full re-authentication on the next {@link #getConnection} call.
     */
    public void invalidateConnection() {
        synchronized (this) {
            gh = null;
            lastAppToken = null;
            if (tokenProvider != null) {
                tokenProvider.invalidate();
            }
        }
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return DESCRIPTOR;
    }

    public static final class DescriptorImpl extends Descriptor<GhprbGitHubAuth> {

        @Override
        public String getDisplayName() {
            return "GitHub Auth";
        }

        /**
         * Stapler helper method.
         *
         * @param context       the context.
         * @param serverAPIUrl  the github api server url.
         * @param credentialsId the credentialsId from the credentials plugin
         * @return list box model.
         */
        public ListBoxModel doFillCredentialsIdItems(
                @AncestorInPath Item context,
                @QueryParameter String serverAPIUrl,
                @QueryParameter String credentialsId
        ) {
            List<DomainRequirement> domainRequirements = URIRequirementBuilder.fromUri(serverAPIUrl).build();

            List<CredentialsMatcher> matchers = new ArrayList<>(INITIAL_CAPACITY);
            if (!StringUtils.isEmpty(credentialsId)) {
                matchers.add(0, CredentialsMatchers.withId(credentialsId));
            }

            matchers.add(CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class));
            matchers.add(CredentialsMatchers.instanceOf(StringCredentials.class));
            matchers.add(CredentialsMatchers.instanceOf(FileCredentials.class));
            try {
                Class<?> appCredClass = Class.forName(GITHUB_APP_CREDENTIALS_CLASS);
                matchers.add(CredentialsMatchers.instanceOf(appCredClass));
            } catch (ClassNotFoundException ignored) {
                // github-branch-source plugin not installed
            }

            List<StandardCredentials> credentials = CredentialsProvider.lookupCredentials(
                    StandardCredentials.class,
                    context,
                    ACL.SYSTEM,
                    domainRequirements
            );

            return new StandardListBoxModel()
                    .withMatching(
                            CredentialsMatchers.anyOf(
                                    matchers.toArray(new CredentialsMatcher[0])),
                            credentials
                    );
        }

        @POST
        public FormValidation doCreateApiToken(
                @QueryParameter("serverAPIUrl") final String serverAPIUrl,
                @QueryParameter("credentialsId") final String credentialsId,
                @QueryParameter("username") final String username,
                @QueryParameter("password") final String password) {
            try {

                Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);

                GitHubBuilder builder = new GitHubBuilder()
                        .withEndpoint(serverAPIUrl)
                        .withConnector(new HttpConnectorWithJenkinsProxy());

                if (StringUtils.isEmpty(credentialsId)) {
                    if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
                        return FormValidation.error("Username and Password required");
                    }

                    builder.withPassword(username, password);
                } else {
                    StandardCredentials credentials = Ghprb.lookupCredentials(null, credentialsId, serverAPIUrl);
                    if (credentials instanceof StandardUsernamePasswordCredentials) {
                        StandardUsernamePasswordCredentials upCredentials = (StandardUsernamePasswordCredentials) credentials;
                        builder.withPassword(upCredentials.getUsername(), upCredentials.getPassword().getPlainText());
                    } else {
                        return FormValidation.error("No username/password credentials provided");
                    }
                }
                GitHub gh = builder.build();
                GHAuthorization token = gh.createToken(Arrays.asList(GHAuthorization.REPO_STATUS,
                        GHAuthorization.REPO), "Jenkins GitHub Pull Request Builder", null);
                String tokenId;
                try {
                    tokenId = Ghprb.createCredentials(serverAPIUrl, token.getToken());
                } catch (Exception e) {
                    tokenId = "Unable to create credentials: " + e.getMessage();
                }

                return FormValidation.ok("Access token created: " + token.getToken() + " token CredentialsID: " + tokenId);
            } catch (IOException ex) {
                return FormValidation.error("GitHub API token couldn't be created: " + ex.getMessage());
            }
        }

        public FormValidation doCheckServerAPIUrl(@QueryParameter String value) {
            if ("https://api.github.com".equals(value)) {
                return FormValidation.ok();
            }
            if (value.endsWith("/api/v3") || value.endsWith("/api/v3/")) {
                return FormValidation.ok();
            }
            return FormValidation.warning("GitHub API URI is \"https://api.github.com\". GitHub Enterprise API URL ends with \"/api/v3\"");
        }

        @POST
        public FormValidation doCheckRepoAccess(
                @QueryParameter("serverAPIUrl") final String serverAPIUrl,
                @QueryParameter("credentialsId") final String credentialsId,
                @QueryParameter("repo") final String repo,
                @QueryParameter("appId") final String appId,
                @QueryParameter("installationId") final String installationId) {

            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);

            try {
                GitHubBuilder builder = getBuilder(null, serverAPIUrl, credentialsId, appId, installationId);
                if (builder == null) {
                    return FormValidation.error("Unable to look up GitHub credentials using ID: " + credentialsId + "!!");
                }
                GitHub gh = builder.build();
                GHRepository repository = gh.getRepository(repo);
                StringBuilder sb = new StringBuilder();
                sb.append("User has access to: ");
                List<String> permissions = new ArrayList<>(INITIAL_CAPACITY);
                if (repository.hasAdminAccess()) {
                    permissions.add("Admin");
                }
                if (repository.hasPushAccess()) {
                    permissions.add("Push");
                }
                if (repository.hasPullAccess()) {
                    permissions.add("Pull");
                }
                sb.append(Joiner.on(", ").join(permissions));

                return FormValidation.ok(sb.toString());
            } catch (Exception ex) {
                return FormValidation.error("Unable to connect to GitHub API: " + ex);
            }
        }

        @POST
        public FormValidation doTestGithubAccess(
                @QueryParameter("serverAPIUrl") final String serverAPIUrl,
                @QueryParameter("credentialsId") final String credentialsId,
                @QueryParameter("appId") final String appId,
                @QueryParameter("installationId") final String installationId) {

            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);

            try {
                GitHubBuilder builder = getBuilder(null, serverAPIUrl, credentialsId, appId, installationId);
                if (builder == null) {
                    return FormValidation.error("Unable to look up GitHub credentials using ID: " + credentialsId + "!!");
                }
                GitHub gh = builder.build();

                StandardCredentials cred = StringUtils.isEmpty(credentialsId)
                        ? null : Ghprb.lookupCredentials(null, credentialsId, serverAPIUrl);
                boolean isAppMode = (!StringUtils.isEmpty(appId) && !StringUtils.isEmpty(installationId))
                        || (cred != null && GITHUB_APP_CREDENTIALS_CLASS.equals(cred.getClass().getName()));

                if (isAppMode) {
                    gh.getRateLimit();
                    String comment = String.format(
                            "Connected to %s using GitHub App credentials",
                            serverAPIUrl);
                    return FormValidation.ok(comment);
                }

                GHMyself me = gh.getMyself();
                String name = me.getName();
                String email = me.getEmail();
                String login = me.getLogin();

                String comment = String.format("Connected to %s as %s (%s) login: %s", serverAPIUrl, name, email, login);
                return FormValidation.ok(comment);
            } catch (Exception ex) {
                return FormValidation.error("Unable to connect to GitHub API: " + ex);
            }
        }


        public FormValidation doTestComment(
                @QueryParameter("serverAPIUrl") final String serverAPIUrl,
                @QueryParameter("credentialsId") final String credentialsId,
                @QueryParameter("repo") final String repoName,
                @QueryParameter("issueId") final int issueId,
                @QueryParameter("message1") final String comment,
                @QueryParameter("appId") final String appId,
                @QueryParameter("installationId") final String installationId) {
            try {
                GitHubBuilder builder = getBuilder(null, serverAPIUrl, credentialsId, appId, installationId);
                if (builder == null) {
                    return FormValidation.error("Unable to look up GitHub credentials using ID: " + credentialsId + "!!");
                }
                GitHub gh = builder.build();
                GHRepository repo = gh.getRepository(repoName);
                GHIssue issue = repo.getIssue(issueId);
                issue.comment(comment);

                return FormValidation.ok("Issued comment to issue: " + issue.getHtmlUrl());
            } catch (Exception ex) {
                return FormValidation.error("Unable to issue comment: " + ex);
            }
        }

        public FormValidation doTestUpdateStatus(
                @QueryParameter("serverAPIUrl") final String serverAPIUrl,
                @QueryParameter("credentialsId") final String credentialsId,
                @QueryParameter("repo") final String repoName,
                @QueryParameter("sha1") final String sha1,
                @QueryParameter("state") final GHCommitState state,
                @QueryParameter("url") final String url,
                @QueryParameter("message2") final String message,
                @QueryParameter("context") final String context,
                @QueryParameter("appId") final String appId,
                @QueryParameter("installationId") final String installationId) {
            try {
                GitHubBuilder builder = getBuilder(null, serverAPIUrl, credentialsId, appId, installationId);
                if (builder == null) {
                    return FormValidation.error("Unable to look up GitHub credentials using ID: " + credentialsId + "!!");
                }
                GitHub gh = builder.build();
                GHRepository repo = gh.getRepository(repoName);
                repo.createCommitStatus(sha1, state, url, message, context);
                return FormValidation.ok("Updated status of: " + sha1);
            } catch (Exception ex) {
                return FormValidation.error("Unable to update status: " + ex);
            }
        }

        public ListBoxModel doFillStateItems(@QueryParameter("state") String state) {
            ListBoxModel items = new ListBoxModel();
            for (GHCommitState commitState : GHCommitState.values()) {

                items.add(commitState.toString(), commitState.toString());
                if (state.equals(commitState.toString())) {
                    items.get(items.size() - 1).selected = true;
                }
            }

            return items;
        }
    }
}
