package com.k4ch0w.pwnback;


import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.*;

import static java.lang.Thread.sleep;


/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBackMediator {
    private final String waybackString = "http://web.archive.org/cdx/search/cdx?url=%s&limit=%s&from=%s&to=%s" +
            "&showResumeKey=True&collapse=digest";//Remove duplicates based on page digest
    private final int numOfDrivers = 2;
    private final int numOfParsers = 10;
    private final int recordLimit;
    private final String yearStart;
    private final String yearEnd;
    private final List<PwnBackLogEntry> log = new ArrayList<PwnBackLogEntry>();
    private final PwnBackGui gui = new PwnBackGui(this);
    private final ExecutorService docParsers = Executors.newFixedThreadPool(numOfParsers);
    private final ExecutorService webDrivers = Executors.newFixedThreadPool(numOfDrivers);
    private BlockingQueue<PwnBackDocument> documentsToParse = new ArrayBlockingQueue<>(1000);
    private BlockingQueue<PwnBackURL> urlsToRequest = new ArrayBlockingQueue<>(10000);


    public PwnBackMediator() {
        recordLimit = 1000;
        yearStart = "2016";
        yearEnd = "2017";
    }

    public void start(){
        addDomain("sequence.com");
        for (int i = 0; i < numOfParsers; i++) {
            docParsers.execute(new PwnBackParser(this));
        }

        for (int i = 0; i < numOfDrivers; i++) {
            webDrivers.execute(new PwnBackWebDriver(this));
        }
    }

    public PwnBackGui getGui() {
        return gui;
    }

    public List<PwnBackLogEntry> getLog() {
        return log;
    }

    public void addLog(String s){
        addLog(new PwnBackLogEntry(s));
    }
    public void addLog(PwnBackLogEntry e) {
        synchronized (log) {
            log.add(e);
            gui.notifyUpdate();
        }
    }

    public void addDocument(PwnBackDocument doc) {
             documentsToParse.add(doc);
    }

    public void addURL(PwnBackURL url) {
            urlsToRequest.add(url);
    }

    public PwnBackURL getURL() {
        PwnBackURL url = null;
        try {
            url = urlsToRequest.take();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return url;
    }

    public PwnBackDocument getDocument() {
        PwnBackDocument doc = null;
        try {
           doc = documentsToParse.take();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return doc;
    }

    public void addDomain(String domain) {
        final String waybackApiGetDomain = String.format(waybackString, domain, recordLimit, yearStart, yearEnd);
        addURL(new PwnBackURL(waybackApiGetDomain, PwnBackType.WAYBACKAPI));
    }
}



