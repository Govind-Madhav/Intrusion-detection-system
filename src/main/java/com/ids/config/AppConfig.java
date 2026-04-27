package com.ids.config;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class AppConfig {
    private static final Map<String, String> CONFIG = new HashMap<>();

    static {
        // Default configuration
        CONFIG.put("log.file.path", "alerts.log");
        CONFIG.put("log.console.enabled", "true");
        CONFIG.put("detection.enable_syn_scan", "true");
        CONFIG.put("detection.enable_icmp_flood", "true");
        CONFIG.put("detection.enable_risky_port", "true");
        CONFIG.put("alert.min_severity", "MEDIUM");
    }

    /**
     * Load configuration from .env file first, then override with real
     * system env vars (real env vars always take priority over .env).
     */
    public static void loadConfig() {
        // 1. Read .env file from project root (so IDS_* vars work on Windows)
        loadDotEnvFile(".env");

        // 2. Map IDS_* env vars → config keys (real env var overrides .env)
        applyEnvVar("IDS_LOG_FILE",    "log.file.path");
        applyEnvVar("IDS_LOG_CONSOLE", "log.console.enabled");
        applyEnvVar("IDS_MIN_SEVERITY","alert.min_severity");

        // 3. Validate
        validateConfig();
    }

    /**
     * Parse a .env file and expose its KEY=VALUE pairs so System.getenv()
     * calls work correctly on Windows where .env files are not loaded by the OS.
     * Lines starting with # and empty lines are ignored.
     */
    private static void loadDotEnvFile(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq < 1) continue;
                String key   = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                // Only set if NOT already a real system env var
                if (System.getenv(key) == null) {
                    System.setProperty(key, value);
                }
            }
        } catch (IOException e) {
            // .env is optional when running inside Spring Boot (spring-dotenv handles it)
            System.out.println("[INFO] No .env file found at: " + filePath + " — using system env vars.");
        }
    }

    /** Reads key from system env OR system properties (covers both real env and .env). */
    private static String getEnv(String key) {
        String val = System.getenv(key);
        return val != null ? val : System.getProperty(key);
    }

    private static void applyEnvVar(String envKey, String configKey) {
        String value = getEnv(envKey);
        if (value != null && !value.isEmpty()) {
            if (configKey.equals("alert.min_severity")) {
                CONFIG.put(configKey, value.toUpperCase());
            } else if (configKey.equals("log.console.enabled")) {
                CONFIG.put(configKey, value.toLowerCase());
            } else {
                CONFIG.put(configKey, value);
            }
        }
    }

    public static String get(String key) {
        return CONFIG.get(key);
    }

    public static String get(String key, String defaultValue) {
        return CONFIG.getOrDefault(key, defaultValue);
    }

    public static boolean getBoolean(String key) {
        String value = CONFIG.get(key);
        return value != null && (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }

    public static String getLogFilePath() {
        return CONFIG.get("log.file.path");
    }

    public static boolean isConsoleLoggingEnabled() {
        return getBoolean("log.console.enabled");
    }

    public static String getMinSeverity() {
        return CONFIG.getOrDefault("alert.min_severity", "MEDIUM");
    }

    public static boolean isDetectorEnabled(String detectorName) {
        String key = "detection.enable_" + detectorName.toLowerCase();
        return getBoolean(key);
    }

    public static void printConfig() {
        System.out.println("[INFO] Application Configuration:");
        CONFIG.forEach((key, value) -> System.out.printf("  %s = %s%n", key, value));
    }

    private static void validateConfig() {
        String minSeverity = CONFIG.get("alert.min_severity");
        if (!isSeverityValid(minSeverity)) {
            System.err.println("[WARN] Invalid minimum severity: " + minSeverity + ", using MEDIUM");
            CONFIG.put("alert.min_severity", "MEDIUM");
        }

        String logPath = CONFIG.get("log.file.path");
        if (logPath != null && !logPath.isEmpty()) {
            try {
                Files.createFile(Paths.get(logPath));
            } catch (Exception e) {
                // File already exists or no write permission — not fatal
            }
        }
    }

    private static boolean isSeverityValid(String severity) {
        return severity != null &&
               (severity.equals("LOW") || severity.equals("MEDIUM") ||
                severity.equals("HIGH") || severity.equals("CRITICAL"));
    }
}
