package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Extracts the SNI (Server Name Indication) hostname from TLS ClientHello packets.
 * Translated from C++ class SNIExtractor in sni_extractor.h / sni_extractor.cpp
 */
public class SNIExtractor {

    // TLS constants (was private constexpr fields in C++ class)
    private static final int CONTENT_TYPE_HANDSHAKE  = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO  = 0x01;
    private static final int EXTENSION_SNI           = 0x0000;
    private static final int SNI_TYPE_HOSTNAME       = 0x00;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Check if the payload looks like a TLS ClientHello record.
     * Translated from SNIExtractor::isTLSClientHello()
     */
    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;

        // Byte 0: Content Type (should be 0x16 = Handshake)
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // Bytes 1-2: TLS Version (0x0300–0x0304)
        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Bytes 3-4: Record length
        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;

        // Byte 5: Handshake type (should be 0x01 = ClientHello)
        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    /**
     * Extract the SNI hostname from a TLS ClientHello payload.
     * Returns Optional.empty() if not found or payload is not a valid ClientHello.
     * Translated from SNIExtractor::extract()
     */
    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) {
            return Optional.empty();
        }

        // Skip TLS record header (5 bytes)
        int offset = 5;

        // Skip handshake header: type(1) + length(3) = 4 bytes
        // (type already verified; read the 3-byte length)
        if (offset + 4 > length) return Optional.empty();
        offset += 4; // skip handshake header

        // Client Hello body
        // Client version (2 bytes)
        if (offset + 2 > length) return Optional.empty();
        offset += 2;

        // Random (32 bytes)
        if (offset + 32 > length) return Optional.empty();
        offset += 32;

        // Session ID
        if (offset >= length) return Optional.empty();
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        // Cipher suites
        if (offset + 2 > length) return Optional.empty();
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;

        // Compression methods
        if (offset >= length) return Optional.empty();
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        // Extensions
        if (offset + 2 > length) return Optional.empty();
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; // Truncated — try to parse anyway
        }

        // Parse extensions to find SNI (type 0x0000)
        while (offset + 4 <= extensionsEnd) {
            int extensionType   = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                // SNI list length (2) + SNI type (1) + SNI length (2) + SNI value
                if (extensionLength < 5) break;

                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;

                int sniType   = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                // Extract the hostname as ASCII string
                String sni = new String(payload, offset + 5, sniLength);
                return Optional.of(sni);
            }

            offset += extensionLength;
        }

        return Optional.empty();
    }

    // -------------------------------------------------------------------------
    // Private helper
    // -------------------------------------------------------------------------

    /** Read 2 bytes as big-endian unsigned int. */
    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
