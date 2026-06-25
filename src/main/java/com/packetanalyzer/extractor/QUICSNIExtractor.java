package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Simplified QUIC SNI extractor — searches for TLS ClientHello
 * inside QUIC Initial packet CRYPTO frames.
 * Translated from C++ class QUICSNIExtractor in sni_extractor.h / sni_extractor.cpp
 */
public class QUICSNIExtractor {

    /**
     * Check if the payload looks like a QUIC Initial (long-header) packet.
     * Translated from QUICSNIExtractor::isQUICInitial()
     */
    public static boolean isQUICInitial(byte[] payload, int length) {
        if (length < 5) return false;
        // Long header form bit: high bit of first byte must be set
        return (payload[0] & 0x80) != 0;
    }

    /**
     * Attempt to extract the SNI from within a QUIC Initial packet.
     * Uses a simplified pattern search for an embedded TLS ClientHello.
     * Translated from QUICSNIExtractor::extract()
     */
    public static Optional<String> extract(byte[] payload, int length) {
        if (!isQUICInitial(payload, length)) return Optional.empty();

        // Search for TLS ClientHello handshake type byte (0x01)
        // embedded within QUIC CRYPTO frames
        for (int i = 0; i + 50 < length; i++) {
            if ((payload[i] & 0xFF) == 0x01) {
                // Try to read a fake TLS record starting 5 bytes before the handshake type
                if (i >= 5) {
                    Optional<String> result = SNIExtractor.extract(payload, length);
                    if (result.isPresent()) return result;
                }
            }
        }

        return Optional.empty();
    }
}
