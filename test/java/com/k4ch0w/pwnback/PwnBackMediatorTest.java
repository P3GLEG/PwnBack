package com.k4ch0w.pwnback;

import org.junit.Test;

import static java.lang.Thread.sleep;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackMediatorTest {
    @Test
    public void addDomain() throws Exception {
        PwnBackMediator m = new PwnBackMediator();
        m.addDomain("news.ycombinator.com");
        try {
            sleep(90000);
        } catch (Exception e) {

        }
    }

}