package com.k4ch0w.pwnback;
import com.machinepublishers.jbrowserdriver.JBrowserDriver;
import com.machinepublishers.jbrowserdriver.Settings;
import com.machinepublishers.jbrowserdriver.Timezone;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Node;

import java.util.ArrayList;
import java.util.concurrent.*;


/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBackWebCrawler {
    private BlockingQueue<String> htmlDocuments = new ArrayBlockingQueue<String>(100);
    private final String waybackString = "http://web.archive.org/cdx/search/cdx?url=%s&limit=%s&from=%s&to=%s" +
            "&showResumeKey=True&collapse=digest";//Remove duplicates based on page digest
    private final String waybackRequestString = "https://web.archive.org/web/%s/%s";
    private final int recordLimit;
    private final String yearStart;
    private final String yearEnd;
    private final ArrayList<Archive> archives = new ArrayList<>();
    private final JBrowserDriver driver = new JBrowserDriver(Settings.builder().
                timezone(Timezone.AMERICA_NEWYORK).build());

    public PwnBackWebCrawler(){
        recordLimit = 1000;
        yearStart = "2000";
        yearEnd = "2017";
        for(int i =0; i < 10; i++){
            new Thread(new DocumentParserWorker(htmlDocuments)).start();
        }
    }


    public void addURL(String url) {
        final String waybackUrl = String.format(waybackString, url, recordLimit, yearStart, yearEnd);
        driver.get(waybackUrl);
        String[] lines = driver.getPageSource().replaceAll("\\<.*?>","").split("\\r?\\n");
        for (String i :
                lines) {
            String[] archive = (i.split(" "));
            archives.add(new Archive(archive[0],archive[1],archive[2],archive[3],archive[4], archive[5], archive[6]));
        }
        for (Archive a:
             archives) {
            String URL = String.format(waybackRequestString, a.timestamp, a.original);
            driver.get(URL);
            String html = driver.getPageSource();
            htmlDocuments.add(html);
        }
    }


}


