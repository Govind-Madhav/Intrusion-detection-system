package com.ids.output;

import com.ids.model.AlertEvent;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicInteger;

public class AlertLogger {
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
    
    private final String logFilePath;
    private final boolean consoleOutput;
    private final AtomicInteger alertCount = new AtomicInteger(0);
    private volatile boolean closed = false;

    public AlertLogger(String logFilePath, boolean consoleOutput) {
        this.logFilePath = logFilePath;
        this.consoleOutput = consoleOutput;
        
        // Write header
        if (logFilePath != null) {
            writeToFile(generateHeader());
        }
    }

    /**
     * Log an alert event to file and/or console
     *
     * @param alert the alert event to log
     */
    public synchronized void log(AlertEvent alert) {
        if (alert == null || closed) {
            return;
        }

        int alertNumber = alertCount.incrementAndGet();
        String logEntry = formatAlert(alert, alertNumber);

        if (consoleOutput) {
            System.out.println(logEntry);
        }

        if (logFilePath != null) {
            writeToFile(logEntry);
        }
    }

    /**
     * Log multiple alerts
     *
     * @param alerts list of alerts to log
     */
    public synchronized void logBatch(java.util.List<AlertEvent> alerts) {
        if (alerts == null || closed) {
            return;
        }

        for (AlertEvent alert : alerts) {
            log(alert);
        }
    }

    /**
     * Get total alerts logged
     *
     * @return total count
     */
    public int getTotalAlerts() {
        return alertCount.get();
    }

    /**
     * Close the logger
     */
    public synchronized void close() {
        if (!closed) {
            if (logFilePath != null) {
                writeToFile(generateFooter());
            }
            closed = true;
        }
    }

    private String formatAlert(AlertEvent alert, int alertNumber) {
        String timestamp = TIMESTAMP_FORMATTER.format(Instant.ofEpochMilli(alert.getTimestamp()));
        
        return String.format(
            "[%s] [Alert #%d] [%s] [%s]\n" +
            "  Detector: %s\n" +
            "  Type: %s\n" +
            "  Severity: %s\n" +
            "  Source: %s:%d\n" +
            "  Destination: %s:%d\n" +
            "  Protocol: %s\n" +
            "  Message: %s\n" +
            "  Alert ID: %s\n" +
            "  ---",
            timestamp, alertNumber, alert.getSeverity(), alert.getAlertType(),
            alert.getDetectorName(),
            alert.getAlertType(),
            alert.getSeverity(),
            alert.getSourceIP(), alert.getSourcePort(),
            alert.getDestinationIP(), alert.getDestinationPort(),
            alert.getProtocol(),
            alert.getMessage(),
            alert.getAlertId()
        );
    }

    private synchronized void writeToFile(String content) {
        if (logFilePath == null) {
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFilePath, true))) {
            writer.write(content);
            writer.newLine();
            writer.flush();
        } catch (IOException e) {
            System.err.printf("[ERROR] Failed to write to alert log: %s%n", e.getMessage());
        }
    }

    private String generateHeader() {
        return String.format(
            "========================================\n" +
            "INTRUSION DETECTION SYSTEM - ALERT LOG\n" +
            "Started: %s\n" +
            "========================================",
            TIMESTAMP_FORMATTER.format(Instant.now())
        );
    }

    private String generateFooter() {
        return String.format(
            "========================================\n" +
            "Total Alerts Logged: %d\n" +
            "Closed: %s\n" +
            "========================================",
            alertCount.get(),
            TIMESTAMP_FORMATTER.format(Instant.now())
        );
    }
}
