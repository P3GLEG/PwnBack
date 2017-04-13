package com.k4ch0w.pwnback;


import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeModel;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
    private final List<PwnBackTableEntry> tableEntries = new ArrayList<>();
    private final PwnBackGUI gui = new PwnBackGUI(this);
    private final BlockingQueue<PwnBackDocument> documentsToParse = new ArrayBlockingQueue<>(1000);
    private final BlockingQueue<PwnBackURL> urlsToRequest = new ArrayBlockingQueue<>(10000);
    private ExecutorService docParsers;
    private ExecutorService webDrivers;

    public PwnBackMediator() {
        recordLimit = 1000;
        yearStart = Integer.toString(PwnBackSettings.startYear);
        yearEnd = Integer.toString(PwnBackSettings.endYear);
    }

    void start() {
        LOG_INFO("Marty McFly: Wait a minute. Wait a minute, Doc. Ah..." +
                " Are you telling me that you built a time machine... out of a DeLorean?");
        LOG_INFO("Dr. Emmett Brown: The way I see it, if you're gonna build a time machine into a car," +
                " why not do it with some *style?*");
        docParsers = Executors.newFixedThreadPool(PwnBackSettings.numofHttpResponseParsers);
        webDrivers = Executors.newFixedThreadPool(PwnBackSettings.numOfJSWebDrivers);
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

    List<PwnBackTableEntry> getLog() {
        return tableEntries;
    }

    void LOG_DEBUG(String logMsg) {
        if (PwnBackSettings.debug) {
            LOG(new PwnBackTableEntry(logMsg, PwnBackType.LOG_DEBUG));
        }
    }

    void LOG_ERROR(String logMsg) {
        LOG(new PwnBackTableEntry(logMsg, PwnBackType.LOG_ERROR));
    }

    void LOG_INFO(String logMsg) {
        LOG(new PwnBackTableEntry(logMsg, PwnBackType.LOG_INFO));
    }

    private void LOG(PwnBackTableEntry entry) {
        logTableLock.lock();
        try {
            tableEntries.add(entry);
            gui.notifyUpdate();
        } finally {
            logTableLock.unlock();
        }


    }

    void addPath(PwnBackNode entry) {
        treeModelLock.lock();
        try {
            gui.addURL(entry);
        } finally {
            treeModelLock.unlock();
        }
    }

    private String generatePath(TreeModel model, Object object, String indent) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) object;
        if (node.getParent() != null && node.getParent().equals(model.getRoot())) {
            indent = "/"; //root node case otherwise will be // instead of /
        }
        StringBuilder myRow = new StringBuilder(indent + object + System.getProperty("line.separator"));
        for (int i = 0; i < model.getChildCount(object); i++) {
            myRow.append(generatePath(model, model.getChild(object, i), indent + object + "/"));
        }
        return myRow.toString();
    }

    boolean exportPathsToFile(TreeModel tree, Path filename) {
        Charset charset = Charset.forName("UTF-8");
        String s = generatePath(tree, tree.getRoot(), "");
        try (BufferedWriter writer = Files.newBufferedWriter(filename, charset)) {
            writer.write(s, 0, s.length());
        } catch (IOException x) {
            System.err.format("IOException: %s%n", x);
            return false;
        }
        return true;
    }

    void addDocument(PwnBackDocument doc) {
        documentsToParse.add(doc);
    }

    void addURL(PwnBackURL url) {
        urlsToRequest.add(url);
    }

    void cancel() {
        LOG_INFO("Putting the beast to sleep");
        webDrivers.shutdownNow();
        docParsers.shutdownNow();
    }

    PwnBackURL getURL() throws InterruptedException {
        PwnBackURL url;
        url = urlsToRequest.take();
        return url;
    }

    PwnBackDocument getDocument() throws InterruptedException {
        PwnBackDocument doc;
        doc = documentsToParse.take();
        return doc;
    }

    void addDomain(String domain) {
        final String waybackApiGetDomain = String.format(waybackString, domain, recordLimit, yearStart, yearEnd);
        addURL(new PwnBackURL(waybackApiGetDomain, PwnBackType.WAYBACKAPI));
    }
}



