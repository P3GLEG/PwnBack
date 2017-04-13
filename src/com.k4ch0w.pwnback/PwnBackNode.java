package com.k4ch0w.pwnback;

import java.util.ArrayList;

/**
 * Created by pganea on 4/7/17.
 */
public class PwnBackNode {
    private final ArrayList<PwnBackDocument> documents = new ArrayList<>();
    private String path;

    /*
        Root init only
     */
    PwnBackNode(String path) {
        this.path = path;
    }

    PwnBackNode(String path, PwnBackDocument doc) {
        this.path = path;
        documents.add(doc);
    }

    String getPath() {
        return path;
    }

    PwnBackDocument getFirstDocument() {
        return documents.get(0);
    }

    void addDocument(PwnBackDocument doc) {
        documents.add(doc);
    }

    ArrayList<PwnBackDocument> getDocuments() {
        return documents;
    }

    @Override
    public String toString() {
        return path;
    }


}
