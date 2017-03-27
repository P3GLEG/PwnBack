package com.k4ch0w.pwnback;


import org.junit.Test;

/**
 * Created by k4ch0w on 3/26/17.
 */
public class PwnBackWebCrawlerTest {
    @Test
    public void addURL() throws Exception {
        PwnBackWebCrawler c = new PwnBackWebCrawler();
        c.addURL("http://sequence.com");
    }

}