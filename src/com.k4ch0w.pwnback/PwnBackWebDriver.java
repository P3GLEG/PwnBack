package com.k4ch0w.pwnback;

import com.machinepublishers.jbrowserdriver.JBrowserDriver;
import com.machinepublishers.jbrowserdriver.Settings;
import com.machinepublishers.jbrowserdriver.Timezone;
import java.util.logging.Level;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackWebDriver implements Runnable {
    private final PwnBackMediator mediator;
    private final JBrowserDriver driver;

    public PwnBackWebDriver(PwnBackMediator mediator) {
        this.mediator = mediator;
        driver = new JBrowserDriver(Settings.builder().
                timezone(Timezone.AMERICA_NEWYORK).
                ssl("trustanything"). //TODO: Change this when you have time
                loggerLevel(Level.OFF). //Annoying failed connections spamming logs
                build());
    }

    @Override
    public void run() {
        while (true) {
            PwnBackURL url = mediator.getURL();
            System.out.println("Processing: " + url);
            driver.get(url.getURL());
            String html = driver.getPageSource();
            switch (url.getType()) {
                case WAYBACKAPI:
                    mediator.addDocument(new PwnBackDocument(html, PwnBackType.WAYBACKAPI));
                    break;
                case ROBOTS:
                    mediator.addDocument(new PwnBackDocument(html, PwnBackType.ROBOTS));
                    break;
                case SITEMAPXML:
                    mediator.addDocument(new PwnBackDocument(html, PwnBackType.SITEMAPXML));
                    break;
                case HTML:
                    mediator.addDocument(new PwnBackDocument(html, PwnBackType.HTML));
                    break;
            }
        }
    }

}
