package com.k4ch0w.pwnback;

import java.util.ArrayList;

/**
 * Created by pganea on 4/7/17.
 */
public class PwnBackNode {
    private String path;
    private final ArrayList<PwnBackDocument> documents = new ArrayList<>();

    /*
        Root init only
     */
    public PwnBackNode(String path) {
        this.path = path;
    }

    public PwnBackNode(String path, PwnBackDocument doc) {
        this.path = path;
        documents.add(doc);
    }

    public String getPath() {
        return path;
    }

    public PwnBackDocument getFirstDocument() {
        return documents.get(0);
    }

    public void addDocument(PwnBackDocument doc) {
        documents.add(doc);
    }

    public ArrayList<PwnBackDocument> getDocuments() {
        return documents;
    }

    @Override
    public String toString() {
        return path;
    }


}
