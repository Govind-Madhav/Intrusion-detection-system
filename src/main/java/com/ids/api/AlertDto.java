package com.ids.api;

public class AlertDto {
    private String alertId;
    private String detectorName;
    private String severity;
    private String alertType;
    private String sourceIP;
    private int sourcePort;
    private String destinationIP;
    private int destinationPort;
    private String protocol;
    private String message;
    private long timestamp;

    public AlertDto() {}

    public AlertDto(String alertId, String detectorName, String severity, String alertType,
                    String sourceIP, int sourcePort, String destinationIP, int destinationPort,
                    String protocol, String message, long timestamp) {
        this.alertId = alertId;
        this.detectorName = detectorName;
        this.severity = severity;
        this.alertType = alertType;
        this.sourceIP = sourceIP;
        this.sourcePort = sourcePort;
        this.destinationIP = destinationIP;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.message = message;
        this.timestamp = timestamp;
    }

    public String getAlertId()          { return alertId; }
    public String getDetectorName()     { return detectorName; }
    public String getSeverity()         { return severity; }
    public String getAlertType()        { return alertType; }
    public String getSourceIP()         { return sourceIP; }
    public int    getSourcePort()       { return sourcePort; }
    public String getDestinationIP()    { return destinationIP; }
    public int    getDestinationPort()  { return destinationPort; }
    public String getProtocol()         { return protocol; }
    public String getMessage()          { return message; }
    public long   getTimestamp()        { return timestamp; }

    public void setAlertId(String alertId)                  { this.alertId = alertId; }
    public void setDetectorName(String detectorName)        { this.detectorName = detectorName; }
    public void setSeverity(String severity)                { this.severity = severity; }
    public void setAlertType(String alertType)              { this.alertType = alertType; }
    public void setSourceIP(String sourceIP)                { this.sourceIP = sourceIP; }
    public void setSourcePort(int sourcePort)               { this.sourcePort = sourcePort; }
    public void setDestinationIP(String destinationIP)      { this.destinationIP = destinationIP; }
    public void setDestinationPort(int destinationPort)     { this.destinationPort = destinationPort; }
    public void setProtocol(String protocol)                { this.protocol = protocol; }
    public void setMessage(String message)                  { this.message = message; }
    public void setTimestamp(long timestamp)                { this.timestamp = timestamp; }
}
