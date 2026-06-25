package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Extracts the queried domain name from DNS query packets.
 * Translated from C++ class DNSExtractor in sni_extractor.h / sni_extractor.cpp
 */
public class DNSExtractor {

    /**
     * Check if the payload looks like a DNS query (not a response).
     * Translated from DNSExtractor::isDNSQuery()
     */
    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) return false;

        // Byte 2, bit 7 (QR bit): 0 = query, 1 = response
        int flags = payload[2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // This is a response

        // QDCOUNT (bytes 4-5): must be > 0
        int qdCount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        return qdCount > 0;
    }

    /**
     * Extract the first queried domain name from a DNS query payload.
     * Returns Optional.empty() if not a valid query or extraction fails.
     * Translated from DNSExtractor::extractQuery()
     */
    public static Optional<String> extractQuery(byte[] payload, int length) {
        if (!isDNSQuery(payload, length)) return Optional.empty();

        // DNS questions start at byte 12 (after the 12-byte fixed header)
        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLength = payload[offset] & 0xFF;

            if (labelLength == 0) {
                // End of domain name
                break;
            }

            if (labelLength > 63) {
                // Compression pointer or invalid — stop
                break;
            }

            offset++;
            if (offset + labelLength > length) break;

            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength));
            offset += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
