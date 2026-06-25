package com.packetanalyzer.types;

/**
 * Connection state machine states.
 * Translated from C++ enum class ConnectionState in types.h
 */
public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
}
