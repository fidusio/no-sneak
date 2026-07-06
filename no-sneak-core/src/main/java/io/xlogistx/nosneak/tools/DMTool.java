package io.xlogistx.nosneak.tools;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.DomainSecurityManager;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

public class DMTool {
    private static final LogWrapper log = new LogWrapper(DMTool.class);
    private static final String DB_URL = "mongodb://localhost:27017/xlog_datastore_test?replicaSet=rs0";

    enum Command
    implements GetName {
        ADD_USER("add-user"),
        DELETE_USER("delete-user"),
        UPDATE_PASSWORD("update-password"),
        LOGIN("login")
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
            params.hide(Param.PASSWORD.getName());
            Command command = params.enumValue(Param.COMMAND, Command.values());
            SUS.checkIfNull("command is null", command);
            String subject = params.stringValue(Param.SUBJECT);
            String password = params.stringValue(Param.PASSWORD);
            String dbURL = params.stringValue(Param.DB_URL, DB_URL);
            DomainSecurityManager dsm = NoSneakUtil.SINGLETON.createDomainSecManager(dbURL);
            log.getLogger().info("Domain security manager: " + dsm);

            switch (command) {
                case ADD_USER -> {

                    SubjectIdentifier si = dsm.createSubjectID(subject, password, CryptoConst.HashType.ARGON2);
                    System.out.println("Adding user: " + si.getGUID() + " " + si.getSubjectGUID() + " " + si.getSubjectID());

                }
                case DELETE_USER -> {
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
            System.err.println("Usage: command={add-user|delete-user|update-password} subject=[username] password=[password]" );
            e.printStackTrace();
        }

    }
}
