package io.xlogistx.nosneak.app.mock.utility;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;


public final class DataStoreConfig {

    private DataStoreConfig() {}

    public static final class Key {
        public static final String ENGINE = "engine";
        public static final String HOST = "host";
        public static final String PORT = "port";
        public static final String DB_NAME = "db_name";
        public static final String PATH = "path";
        public static final String USER = "user";
        public static final String PASSWORD = "password";

        private Key() {}
    }

    private static final String DIR_NAME = ".nosneak";
    private static final String FILE_NAME = "datastore.properties";

    public static Path configFile() {
        return Paths.get(System.getProperty("user.home"), DIR_NAME, FILE_NAME);
    }

    public static boolean exists() {
        return Files.isRegularFile(configFile());
    }

    public static Properties load() throws IOException {
        Properties props = new Properties();
        Path file = configFile();
        if (Files.isRegularFile(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            }
        }
        return props;
    }

    public static void save(Properties props) throws IOException {
        Path file = configFile();
        Files.createDirectories(file.getParent());
        try (OutputStream out = Files.newOutputStream(file)) {
            props.store(out, "NoSneak datastore configuration");
        }
    }
}