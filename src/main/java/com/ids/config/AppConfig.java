package com.ids.config;

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
     * Load configuration from environment variables or use defaults
     */
    public static void loadConfig() {
        // Check for log file path override
        String logPath = System.getenv("IDS_LOG_FILE");
        if (logPath != null && !logPath.isEmpty()) {
            CONFIG.put("log.file.path", logPath);
        }

        // Check for console output override
        String consoleEnabled = System.getenv("IDS_LOG_CONSOLE");
        if (consoleEnabled != null) {
            CONFIG.put("log.console.enabled", consoleEnabled.toLowerCase());
        }

        // Check for min severity override
        String minSeverity = System.getenv("IDS_MIN_SEVERITY");
        if (minSeverity != null && !minSeverity.isEmpty()) {
            CONFIG.put("alert.min_severity", minSeverity.toUpperCase());
        }

        // Validate configuration
        validateConfig();
    }

    /**
     * Get configuration value
     *
     * @param key configuration key
     * @return configuration value or null if not found
     */
    public static String get(String key) {
        return CONFIG.get(key);
    }

    /**
     * Get configuration value with default fallback
     *
     * @param key configuration key
     * @param defaultValue default value if not found
     * @return configuration value or default
     */
    public static String get(String key, String defaultValue) {
        return CONFIG.getOrDefault(key, defaultValue);
    }

    /**
     * Get boolean configuration value
     *
     * @param key configuration key
     * @return boolean value
     */
    public static boolean getBoolean(String key) {
        String value = CONFIG.get(key);
        return value != null && (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }

    /**
     * Get log file path
     *
     * @return log file path
     */
    public static String getLogFilePath() {
        return CONFIG.get("log.file.path");
    }

    /**
     * Check if console logging is enabled
     *
     * @return true if enabled
     */
    public static boolean isConsoleLoggingEnabled() {
        return getBoolean("log.console.enabled");
    }

    /**
     * Get minimum alert severity level
     *
     * @return severity level (LOW, MEDIUM, HIGH, CRITICAL)
     */
    public static String getMinSeverity() {
        return CONFIG.getOrDefault("alert.min_severity", "MEDIUM");
    }

    /**
     * Check if detector is enabled
     *
     * @param detectorName detector name
     * @return true if enabled
     */
    public static boolean isDetectorEnabled(String detectorName) {
        String key = "detection.enable_" + detectorName.toLowerCase();
        return getBoolean(key);
    }

    /**
     * Print current configuration
     */
    public static void printConfig() {
        System.out.println("[INFO] Application Configuration:");
        CONFIG.forEach((key, value) -> System.out.printf("  %s = %s%n", key, value));
    }

    private static void validateConfig() {
        // Validate severity levels
        String minSeverity = CONFIG.get("alert.min_severity");
        if (!isSeverityValid(minSeverity)) {
            System.err.println("[WARN] Invalid minimum severity: " + minSeverity + ", using MEDIUM");
            CONFIG.put("alert.min_severity", "MEDIUM");
        }

        // Validate log file path is writable
        String logPath = CONFIG.get("log.file.path");
        if (logPath != null && !logPath.isEmpty()) {
            try {
                // Try to create/access the log file
                Files.createFile(Paths.get(logPath));
            } catch (Exception e) {
                // File might already exist or we don't have write permission
                System.err.printf("[WARN] Log file may not be writable: %s%n", logPath);
            }
        }
    }

    private static boolean isSeverityValid(String severity) {
        return severity != null && 
               (severity.equals("LOW") || severity.equals("MEDIUM") || 
                severity.equals("HIGH") || severity.equals("CRITICAL"));
    }
}
