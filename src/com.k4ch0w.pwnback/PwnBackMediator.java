package com.k4ch0w.pwnback;


import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;


/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBackMediator {
    private final String waybackString = "http://web.archive.org/cdx/search/cdx?url=%s&limit=%s&from=%s&to=%s" +
            "&showResumeKey=True&collapse=digest";//Remove duplicates based on page digest
    private final int recordLimit;
    private final String yearStart;
    private final String yearEnd;
    private final List<String> log = new ArrayList<String>();
    private final Set<String> dict = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>()); //wtf java
    private final ExecutorService docParsers = Executors.newFixedThreadPool(PwnBackSettings.numofHttpResponseParsers);
    private final ExecutorService webDrivers = Executors.newFixedThreadPool(PwnBackSettings.numOfJSWebDrivers);
    private final PwnBackGUI gui = new PwnBackGUI(this);
    private BlockingQueue<PwnBackDocument> documentsToParse = new ArrayBlockingQueue<>(1000);
    private BlockingQueue<PwnBackURL> urlsToRequest = new ArrayBlockingQueue<>(10000);


    public PwnBackMediator() {
        recordLimit = 1000;
        yearStart = Integer.toString(PwnBackSettings.startYear);
        yearEnd = Integer.toString(PwnBackSettings.endYear);
    }

    public void start() {
        for (int i = 0; i < PwnBackSettings.numofHttpResponseParsers; i++) {
            docParsers.execute(new PwnBackParser(this));
        }

        for (int i = 0; i < PwnBackSettings.numOfJSWebDrivers; i++) {
            webDrivers.execute(new PwnBackWebDriver(this));
        }
    }

    public PwnBackGUI getGui() {
        return gui;
    }

    public List<String> getLog() {
        return log;
    }

    public void addPath(String path) {
        if (!dict.contains(path)) {
            dict.add(path);
            synchronized (log) {
                log.add(path);
                gui.notifyUpdate();
            }
        }
    }

    public void exportPathsToFile() {
        Path file = Paths.get(PwnBackSettings.outputDir, "output.txt");
        try {
            Files.write(file, log, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
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



