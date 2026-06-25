package com.packetanalyzer.types;

/**
 * Application type classification.
 * Translated from C++ enum class AppType in types.h
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications (detected via SNI)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    /**
     * Convert AppType to human-readable string.
     * Translated from appTypeToString() in types.cpp
     */
    public String toDisplayString() {
        switch (this) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

    /**
     * Map an SNI/domain string to an AppType.
     * Translated from sniToAppType() in types.cpp
     *
     * @param sni Server Name Indication or domain string
     * @return matching AppType
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;

        String lower = sni.toLowerCase();

        // Google
        if (lower.contains("google") || lower.contains("gstatic") ||
            lower.contains("googleapis") || lower.contains("ggpht") ||
            lower.contains("gvt1")) {
            return GOOGLE;
        }

        // YouTube
        if (lower.contains("youtube") || lower.contains("ytimg") ||
            lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return YOUTUBE;
        }

        // Facebook / Meta
        if (lower.contains("facebook") || lower.contains("fbcdn") ||
            lower.contains("fb.com") || lower.contains("fbsbx") ||
            lower.contains("meta.com")) {
            return FACEBOOK;
        }

        // Instagram (owned by Meta)
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return INSTAGRAM;
        }

        // WhatsApp (owned by Meta)
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return WHATSAPP;
        }

        // Twitter / X
        if (lower.contains("twitter") || lower.contains("twimg") ||
            lower.contains("x.com") || lower.contains("t.co")) {
            return TWITTER;
        }

        // Netflix
        if (lower.contains("netflix") || lower.contains("nflxvideo") ||
            lower.contains("nflximg")) {
            return NETFLIX;
        }

        // Amazon
        if (lower.contains("amazon") || lower.contains("amazonaws") ||
            lower.contains("cloudfront") || lower.contains("aws")) {
            return AMAZON;
        }

        // Microsoft
        if (lower.contains("microsoft") || lower.contains("msn.com") ||
            lower.contains("office") || lower.contains("azure") ||
            lower.contains("live.com") || lower.contains("outlook") ||
            lower.contains("bing")) {
            return MICROSOFT;
        }

        // Apple
        if (lower.contains("apple") || lower.contains("icloud") ||
            lower.contains("mzstatic") || lower.contains("itunes")) {
            return APPLE;
        }

        // Telegram
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return TELEGRAM;
        }

        // TikTok
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") ||
            lower.contains("musical.ly") || lower.contains("bytedance")) {
            return TIKTOK;
        }

        // Spotify
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return SPOTIFY;
        }

        // Zoom
        if (lower.contains("zoom")) {
            return ZOOM;
        }

        // Discord
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return DISCORD;
        }

        // GitHub
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return GITHUB;
        }

        // Cloudflare
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return CLOUDFLARE;
        }

        // SNI present but unrecognized => still mark as HTTPS
        return HTTPS;
    }
}
