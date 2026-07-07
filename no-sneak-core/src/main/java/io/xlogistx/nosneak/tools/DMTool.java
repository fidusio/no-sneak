package io.xlogistx.nosneak.tools;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.MetaToken;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

/**
 * Command-line administration tool for managing subjects (users) and their
 * credentials in the xlogistx datastore.
 * <p>
 * Arguments are passed as {@code key=value} pairs. The {@code password} and
 * {@code new-password} values are hidden from logging.
 * <p>
 * Commands:
 * <ul>
 *   <li>{@code add-subject}     &ndash; create a subject with an ARGON2-hashed password.
 *       Params: {@code subject}, {@code password}.</li>
 *   <li>{@code add-api-key}     &ndash; attach an API key to an existing subject.
 *       Params: {@code subject}, {@code password}, {@code api-key}, optional {@code name}, {@code description}.</li>
 *   <li>{@code login}           &ndash; authenticate a subject.
 *       Params: {@code subject}, {@code password}.</li>
 *   <li>{@code delete-subject}  &ndash; delete a subject after authenticating.
 *       Params: {@code subject}, {@code password}.</li>
 *   <li>{@code update-password} &ndash; change a subject's password after authenticating.
 *       Params: {@code subject}, {@code password}, {@code new-password}.</li>
 * </ul>
 * The optional {@code db-url} param overrides the default MongoDB connection.
 */
public class DMTool {
    private static final LogWrapper log = new LogWrapper(DMTool.class);
    private static final String DB_URL = "mongodb://localhost:27017/xlog_datastore_test?replicaSet=rs0";

    private static final String USAGE =
            "Usage: command=<command> subject=<username> password=<password> [options]\n" +
            "\n" +
            "Commands:\n" +
            "  add-subject      subject=<username> password=<password>\n" +
            "  add-api-key      subject=<username> password=<password> api-key=<token> [name=<name>] [description=<desc>]\n" +
            "  login            subject=<username> password=<password>\n" +
            "  delete-subject   subject=<username> password=<password>\n" +
            "  update-password  subject=<username> password=<password> new-password=<password>\n" +
            "\n" +
            "Options:\n" +
            "  db-url=<url>     override the datastore connection (default: " + DB_URL + ")";

    enum Command
    implements GetName {
        ADD_SUBJECT("add-subject"),
        ADD_API_KEY("add-api-key"),
        LOGIN("login"),
        DELETE_SUBJECT("delete-subject"),
        UPDATE_PASSWORD("update-password"),

        ;

        private final String name;
        Command(String name) {
            this.name = name;
        }
        @Override
        public String getName() { return name; }
    }

    enum Param
    implements GetName {
        API_KEY("api-key"),
        COMMAND("command"),
        SUBJECT("subject"),
        PASSWORD("password"),
        NEW_PASSWORD("new-password"),
        DB_URL("db-url"),

        ;
        private final String name;

        Param(String name) {
            this.name = name;
        }
        /**
         * @return the name of the object
         */
        @Override
        public String getName() {
            return name;
        }
    }

    public static void main(String ...args) {
        try
        {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            params.hide(Param.PASSWORD);
            Command command = params.enumValue(Param.COMMAND, Command.values());
            SUS.checkIfNull("command is null", command);
            String subject = params.stringValue(Param.SUBJECT);
            String password = params.stringValue(Param.PASSWORD);
            String dbURL = params.stringValue(Param.DB_URL, DB_URL);
            DomainSecurityManager dsm = NoSneakUtil.SINGLETON.createDomainSecManager(dbURL);
            log.getLogger().info("Domain security manager: " + dsm);

            switch (command) {
                case ADD_SUBJECT -> {

                    SubjectIdentifier si = dsm.createSubjectID(subject, password, CryptoConst.HashType.ARGON2);
                    System.out.println("Adding subject: " + si.getGUID() + " " + si.getSubjectGUID() + " " + si.getSubjectID());

                }
                case ADD_API_KEY -> {
                    SubjectIdentifier si = dsm.login(subject, password);
                    String apiKeyToken = params.stringValue(Param.API_KEY);
                    String name = params.stringValue(MetaToken.NAME, null);
                    String description = params.stringValue(MetaToken.DESCRIPTION, null);
                    APIKey<String> apiKey = new SubjectAPIKey();
                    apiKey.setAPIKey(apiKeyToken);
                    apiKey.setName(name);
                    apiKey.setDescription(description);
                    apiKey.setCredentialStatus(SecConst.SecStatus.ACTIVE);
                    dsm.createCredential(si, apiKey);
                    System.out.println("Adding API key: " + apiKey.getAPIKey() + " " + apiKey.getCredentialStatus());
                }
                case DELETE_SUBJECT -> {
                    SubjectIdentifier si = dsm.login(subject, password);
                    dsm.deleteSubjectID(si);
                }
                case UPDATE_PASSWORD -> {

                    SubjectIdentifier si = dsm.login(subject, password);
                    String newPassword = params.stringValue(Param.NEW_PASSWORD);
                    CredentialHasher<CIPassword> hasher= SecUtil.lookupCredentialHasher(CryptoConst.HashType.ARGON2.getName());
                    CIPassword newCI = hasher.hash(newPassword);
                    dsm.updateCredential(si, newCI);
                    System.out.println("password updated: " + newCI.getGUID() + " " + newCI.getSubjectGUID());


                }
                case LOGIN -> {
                    dsm.login(subject, password);
                    System.out.println("Logged in as " + subject);
                }

                default -> throw new IllegalStateException("Unexpected value: " + command);
            }


        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println();
            System.err.println(USAGE);
            log.getLogger().log(java.util.logging.Level.SEVERE, "command failed", e);
        }

    }
}
