package com.packetanalyzer.extractor;

import java.util.Optional;

/**
 * Extracts the HTTP Host header from plaintext HTTP request payloads.
 * Translated from C++ class HTTPHostExtractor in sni_extractor.h / sni_extractor.cpp
 */
public class HTTPHostExtractor {

    /** HTTP methods to recognize (first 4 bytes). */
    private static final String[] HTTP_METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    /**
     * Check if the payload starts with a known HTTP method.
     * Translated from HTTPHostExtractor::isHTTPRequest()
     */
    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;
        String start = new String(payload, 0, 4);
        for (String method : HTTP_METHODS) {
            if (start.equals(method)) return true;
        }
        return false;
    }

    /**
     * Extract the Host header value from an HTTP request payload.
     * Returns Optional.empty() if not found.
     * Translated from HTTPHostExtractor::extract()
     */
    public static Optional<String> extract(byte[] payload, int length) {
        if (!isHTTPRequest(payload, length)) return Optional.empty();

        // Search for "Host:" header (case-insensitive)
        for (int i = 0; i + 5 < length; i++) {
            if ((payload[i]     == 'H' || payload[i]     == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                 payload[i + 4] == ':') {

                // Skip "Host:" and any whitespace
                int start = i + 5;
                while (start < length &&
                       (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line (CR or LF)
                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start);
                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos >= 0) {
                        host = host.substring(0, colonPos);
                    }
                    return Optional.of(host.trim());
                }
            }
        }

        return Optional.empty();
    }
}
