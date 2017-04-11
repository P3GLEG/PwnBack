package com.k4ch0w.pwnback;


import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;


/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBackMediator {
    public final ReentrantLock treeModelLock = new ReentrantLock();
    public final ReentrantLock logTableLock = new ReentrantLock();
    private final String waybackString = "http://web.archive.org/cdx/search/cdx?url=%s&limit=%s&from=%s&to=%s" +
            "&showResumeKey=True&collapse=digest";//Remove duplicates based on page digest
    private final int recordLimit;
    private final String yearStart;
    private final String yearEnd;
    private final List<String> tableEntries = new ArrayList<String>();
    private final ConcurrentHashMap<String, LinkedList<String>> dict = new ConcurrentHashMap<String, LinkedList<String>>();
    private final ExecutorService docParsers = Executors.newFixedThreadPool(PwnBackSettings.numofHttpResponseParsers);
    private final ExecutorService webDrivers = Executors.newFixedThreadPool(PwnBackSettings.numOfJSWebDrivers);
    private final PwnBackGUI gui = new PwnBackGUI(this);
    private final BlockingQueue<PwnBackDocument> documentsToParse = new ArrayBlockingQueue<>(1000);
    private final BlockingQueue<PwnBackURL> urlsToRequest = new ArrayBlockingQueue<>(10000);
    public PwnBackMediator() {
        recordLimit = 1000;
        yearStart = Integer.toString(PwnBackSettings.startYear);
        yearEnd = Integer.toString(PwnBackSettings.endYear);
    }

    public void start() {
        addLog("Marty McFly: Wait a minute. Wait a minute, Doc. Ah... Are you telling me that you built a time machine... out of a DeLorean?");
        addLog("Dr. Emmett Brown: The way I see it, if you're gonna build a time machine into a car, why not do it with some *style?*");
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
        return tableEntries;
    }

    public void addLog(String msg) {
        logTableLock.lock();
        try {
            tableEntries.add(msg);
            gui.notifyUpdate();
        } finally {
            logTableLock.unlock();
        }

    }

    public void addPath(PwnBackNode entry) {
        treeModelLock.lock();
        try {
            gui.addURL(entry);
        } finally {
            treeModelLock.unlock();
        }
    }

    public void exportPathsToFile() { //TODO: Parse WebTree
        Path file = Paths.get(PwnBackSettings.outputDir, "output.txt");
        StringBuffer sb = new StringBuffer();
        for (Map.Entry<String, LinkedList<String>> e :
                dict.entrySet()) {
            sb.append(e.getKey() + ":");
            for (String s : e.getValue()) {
                sb.append(s);
            }
            sb.append(System.getProperty("line.separator"));
        }
        Charset charset = Charset.forName("UTF-8");
        String s = sb.toString();
        try (BufferedWriter writer = Files.newBufferedWriter(file, charset)) {
            writer.write(s, 0, s.length());
        } catch (IOException x) {
            System.err.format("IOException: %s%n", x);
        }
    }

    public void addDocument(PwnBackDocument doc) {
        documentsToParse.add(doc);
    }

    public void addURL(PwnBackURL url) {
        urlsToRequest.add(url);
    }

    public void cancel() {
        addLog("Putting the beast to sleep");
        webDrivers.shutdownNow();
        docParsers.shutdownNow();
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



