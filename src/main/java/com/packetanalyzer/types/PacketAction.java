package com.packetanalyzer.types;

/**
 * Action to take on a packet after DPI classification.
 * Translated from C++ enum class PacketAction in types.h
 */
public enum PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block / drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
