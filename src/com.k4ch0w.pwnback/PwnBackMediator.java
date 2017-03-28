package com.k4ch0w.pwnback;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBackMediator {
    private final Logger logger = LoggerFactory.getLogger(PwnBackMediator.class);
    private final String waybackString = "http://web.archive.org/cdx/search/cdx?url=%s&limit=%s&from=%s&to=%s" +
            "&showResumeKey=True&collapse=digest";//Remove duplicates based on page digest
    private final int numOfDrivers = 2;
    private final int numOfParsers = 10;
    private final int recordLimit;
    private final String yearStart;
    private final String yearEnd;
    private final ExecutorService docParsers = Executors.newFixedThreadPool(numOfParsers);
    private final ExecutorService webDrivers = Executors.newFixedThreadPool(numOfDrivers);
    private BlockingQueue<PwnBackDocument> documentsToParse = new ArrayBlockingQueue<PwnBackDocument>(1000);
    private BlockingQueue<PwnBackURL> urlsToRequest = new ArrayBlockingQueue<PwnBackURL>(1000);


    public PwnBackMediator() {
        recordLimit = 1000;
        yearStart = "2016";
        yearEnd = "2017";
        for (int i = 0; i < numOfParsers; i++) {
            docParsers.execute(new DocumentParserWorker(this));
        }
        for (int i = 0; i < numOfDrivers; i++) {
            webDrivers.execute(new PwnBackWebDriver(this));
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
            //TODO: LOG
        }
        return url;
    }

    public PwnBackDocument getDocument() {
        PwnBackDocument doc = null;
        try {
            doc = documentsToParse.take();
        } catch (InterruptedException e) {
            ///TODO:LOG
        }
        return doc;
    }

    public void addDomain(String domain) {
        final String waybackApiGetDomain = String.format(waybackString, domain, recordLimit, yearStart, yearEnd);
        addURL(new PwnBackURL(waybackApiGetDomain, PwnBackType.WAYBACKAPI));
        /*
        URL url = new URL(waybackApiGetDomain);
        URLConnection uc = url.openConnection();
        BufferedReader in = new BufferedReader(
                new InputStreamReader(
                        uc.getInputStream()));
        String inputLine;
        StringBuffer sb = new StringBuffer();

        while ((inputLine = in.readLine()) != null)
            sb.append(inputLine);
        in.close();
        */

    }
}



