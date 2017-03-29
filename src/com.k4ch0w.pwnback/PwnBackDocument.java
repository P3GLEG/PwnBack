package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackDocument {
    private PwnBackType type;
    private String document;

    public PwnBackDocument(String document, PwnBackType type) {
        this.document = document;
        this.type = type;
    }

    public String getDocument() {
        return document;
    }

    public PwnBackType getType() {
        return type;
    }

    @Override
    public String toString() {
        return document;
    }


}
