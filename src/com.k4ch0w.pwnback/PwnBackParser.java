package com.k4ch0w.pwnback;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackParser implements Runnable {
    private final PwnBackMediator mediator;
    private final String waybackRequestString = "http://web.archive.org/web/%s/%s";
    private final String ROBOTS_TXT = "robots.txt";
    private final String SITEMAP_XML = "sitemap.xml";

    public PwnBackParser(PwnBackMediator mediator) {
        this.mediator = mediator;
    }

    @Override
    public void run() {
        while (true) {
            PwnBackDocument doc = mediator.getDocument();
            switch (doc.getType()) {
                case WAYBACKAPI:
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
        html = stripHTMLTags(html);
        Scanner scanner = new Scanner(html);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().toLowerCase();
            String[] temp = line.split(" ");
            if (temp.length == 2) {
                switch (temp[0]) {
                    case "disallow:":
                        mediator.addPath(temp[1]);
                        break;
                    case "allow:":
                        mediator.addPath(temp[1]);
                        break;
                    case "sitemap:":
                        mediator.addPath("Sitemap" + temp[1]);
                        break;
                }
            } else {
                System.out.println(temp);
            }
        }
        scanner.close();
    }

    private void parseHTML(String html) {
        html = removeWaybackToolbar(html);
        Document doc = Jsoup.parse(html);
        Elements links = doc.select("a");
        for (Element link :
                links) {
            String relHref = link.attr("href");
            if (relHref.startsWith("mailto:")) {
                System.out.println("Found email address " + relHref.replace("mailto:", ""));
            } else if (relHref.startsWith("/web/") && relHref.contains("http")) {
                //Wayback machine uses it's domain to serve content thus things are prepended
                // with http://archive.org/web and why I split them here
                String clean = relHref.substring(relHref.indexOf("http"));
                try {
                    String path = new URL(clean).getPath();
                    if (!path.isEmpty() && !path.equals("/")) {
                        mediator.addPath(path);
                    }
                } catch (MalformedURLException e) {
                    System.err.println("Error parsing URL : " + clean);
                }
            } else if (relHref.equals("") || relHref.startsWith("#") || relHref.equals("/")) {
                System.out.println("Empty or starts with #: " + relHref);
                continue;
            } else {
                mediator.addPath(relHref);
            }
        }
    }


    private void parseWayBackAPI(String html) {
        String[] waybackUrls = stripHTMLTags(html).split("\\r?\\n");
        for (String u :
                waybackUrls) {
            String[] archive = u.split(" ");
            if (archive.length == 7) { //Each archive address has 7 values return
                String url = String.format(waybackRequestString, archive[1], archive[2]);
                mediator.addURL(new PwnBackURL(url, PwnBackType.HTML));
                mediator.addURL(new PwnBackURL(url + ROBOTS_TXT, PwnBackType.ROBOTS));
                mediator.addURL(new PwnBackURL(url + SITEMAP_XML, PwnBackType.SITEMAPXML));
            }
        }
    }

    private void parseSitemapXML(String html) {
        DocumentBuilder newDocumentBuilder = null;
        try {
            newDocumentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            org.w3c.dom.Document parse = newDocumentBuilder.parse(new ByteArrayInputStream(html.getBytes()));
            NodeList nodeList = parse.getElementsByTagName("loc");
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    mediator.addPath(node.getTextContent());
                }
            }
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
