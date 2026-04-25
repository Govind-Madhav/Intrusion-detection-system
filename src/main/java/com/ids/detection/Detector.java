package com.ids.detection;

import com.ids.model.AlertEvent;
import com.ids.model.PacketData;

public interface Detector {
  AlertEvent analyze(PacketData packet);
}
