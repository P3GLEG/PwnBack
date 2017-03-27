package com.k4ch0w.pwnback;

import java.util.concurrent.BlockingQueue;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class DocumentParserWorker implements Runnable{
    private BlockingQueue<String> queue;
    public DocumentParserWorker(BlockingQueue<String> queue) {
       this.queue = queue;
    }

    @Override
    public void run(){
        while(true) {
            try {
                String document = queue.take();
                System.out.println(removeWaybackToolbar(document));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
    private String removeWaybackToolbar(String html){
        return html.replaceAll("(?s)<!--.BEGIN.WAYBACK.TOOLBAR.INSERT.-->.*?<!--.END.WAYBACK.TOOLBAR.INSERT.-->",
                "");
    }
}
