package com.k4ch0w.pwnback;

import org.jsoup.Jsoup;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class DocumentParserWorker implements Runnable {
    private final PwnBackMediator mediator;
    private final String waybackRequestString = "http://web.archive.org/web/%s/%s";
    private final String ROBOTS_TXT = "robots.txt";
    private final String SITEMAP_XML = "sitemap.xml";

    public DocumentParserWorker(PwnBackMediator mediator) {
        this.mediator = mediator;
    }

    @Override
    public void run() {
        while (true) {
            PwnBackDocument doc = mediator.getDocument();
            switch (doc.getType()) {
                case WAYBACKAPI:
                    System.out.println("API CALL");
                    parseWayBackAPI(doc.getDocument());
                    break;
                case ROBOTS:
                    parseRobotsTxt(doc.getDocument());
                    break;
                case SITEMAPXML:
                    parseSitemapXML(doc.getDocument());
                    break;
                case HTML:
                    parseHTML(doc.getDocument());
                    break;
                default:
                    System.out.println("fuck if I know");
            }
        }
    }

    private String removeWaybackToolbar(String html) {
        return html.replaceAll("(?s)<!--.BEGIN.WAYBACK.TOOLBAR.INSERT.-->.*?<!--.END.WAYBACK.TOOLBAR.INSERT.-->",
                "");
    }

    private String stripHTMLTags(String html) {
        return Jsoup.parse(html).text();
    }

    private void parseRobotsTxt(String html) {
        System.out.println(html);
    }

    private void parseHTML(String html) {
        System.out.println(html);
    }

    private void parseWayBackAPI(String html) {
        String[] waybackUrls = stripHTMLTags(html).split("\\r?\\n");
        for (String u :
                waybackUrls) {
            String[] archive = u.split(" ");
            String url = String.format(waybackRequestString, archive[1], archive[2]);
            mediator.addURL(new PwnBackURL(url, PwnBackType.HTML));
            mediator.addURL(new PwnBackURL(url + ROBOTS_TXT, PwnBackType.ROBOTS));
            mediator.addURL(new PwnBackURL(url + SITEMAP_XML, PwnBackType.SITEMAPXML));
        }
    }

    private void parseSitemapXML(String html) {
        /*
        String[] pages = html.replaceAll("https?://",
                "\nhttp://").
                split("\n");
        for (String page : pages) {
            if(!page.isEmpty()) {
                try {
                    String filepath = new URL(page).getPath();
                    System.out.println(FilenameUtils.getFullPath(filepath) + FilenameUtils.getName(filepath));
                } catch(MalformedURLException e){
                    e.printStackTrace();
                }
            }
        }
        return "";
        */
        removeWaybackToolbar(html);

    }

}
