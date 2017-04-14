package com.k4ch0w.pwnback;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriverService;
import org.openqa.selenium.remote.DesiredCapabilities;

import java.io.File;


/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackWebDriver implements Runnable {
    private final PwnBackMediator mediator;
    private WebDriver driver = null;

    PwnBackWebDriver(PwnBackMediator mediator) {
        this.mediator = mediator;
        PhantomJSDriverService driverService = new PhantomJSDriverService.Builder()
                .usingPhantomJSExecutable(new File(PwnBackSettings.phatomjsLocation))
                .build();
        DesiredCapabilities capability = new DesiredCapabilities();
        capability.setCapability("takesScreenshot", false);
        String[] args = new String[1];
        args[0] = "";
        if (checkSSLCertPathDefined()) {
            args[0] = "--ssl-certificates-path=" + PwnBackSettings.caBundleLocation;
        }
        capability.setCapability(PhantomJSDriverService.PHANTOMJS_CLI_ARGS, args);
        capability.setCapability("phantomjs.page.settings.userAgent", "Mozilla/5.0 (Windows NT 5.1; rv:22.0) Gecko/20100101 Firefox/22.0");
        driver = new PhantomJSDriver(driverService, capability);
    }

    private boolean checkSSLCertPathDefined() {
        File f = new File(PwnBackSettings.caBundleLocation);
        if (f.exists() && !f.isDirectory()) {
            return true;
        }
        return false;
    }

    @Override
    public void run() {
        try {
            while (true) {
                PwnBackURL url = mediator.getURL();
                driver.get(url.getURL());
                String html = driver.getPageSource();
                switch (url.getType()) {
                    case WAYBACKAPI:
                        mediator.addDocument(new PwnBackDocument(html, url.getURL(), PwnBackType.WAYBACKAPI));
                        break;
                    case ROBOTS:
                        mediator.addDocument(new PwnBackDocument(html, url.getURL(), PwnBackType.ROBOTS));
                        break;
                    case SITEMAPXML:
                        mediator.addDocument(new PwnBackDocument(html, url.getURL(), PwnBackType.SITEMAPXML));
                        break;
                    case HTML:
                        mediator.addDocument(new PwnBackDocument(html, url.getURL(), PwnBackType.HTML));
                        break;
                }
            }
        } catch (InterruptedException e) {
            mediator.LOG_DEBUG("Executor interrupted WebDriver");
            driver.close();
        }
    }

}
