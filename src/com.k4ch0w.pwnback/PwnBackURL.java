package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackURL {
    private final String url;
    private PwnBackType type;

    PwnBackURL(String url, PwnBackType type) {
        this.url = url;
        this.type = type;
    }

    PwnBackType getType() {
        return type;
    }

    String getURL() {
        return url;
    }

    @Override
    public String toString() {
        return url;
    }
}
