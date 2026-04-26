package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

import java.util.Optional;

public interface Detector {
    /**
     * Analyzes a packet and returns an alert if suspicious activity is detected.
     *
     * @param packet the packet to analyze
     * @return an Optional containing an AlertEvent if suspicious activity is detected, empty otherwise
     */
    Optional<AlertEvent> detect(PacketData packet);

    /**
     * Returns the name of this detector.
     *
     * @return detector name
     */
    String getName();
}
