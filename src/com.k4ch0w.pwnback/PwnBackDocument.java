package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackDocument {
    private PwnBackType type;
    private String document;
    private String urlFoundAt;

    PwnBackDocument(String document, String urlFoundAt, PwnBackType type) {
        this.document = document;
        this.urlFoundAt = urlFoundAt;
        this.type = type;
    }

    String getDocument() {
        return document;
    }

    PwnBackType getType() {
        return type;
    }

    String getUrlFoundAt() {
        return urlFoundAt;
    }

    @Override
    public String toString() {
        return urlFoundAt;
    }


}
