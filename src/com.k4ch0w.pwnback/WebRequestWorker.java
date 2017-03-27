package com.k4ch0w.pwnback;

import java.util.concurrent.BlockingQueue;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class WebRequestWorker implements Runnable {
    private BlockingQueue<String> queue;

    public WebRequestWorker(BlockingQueue<String> queue){
        this.queue = queue;
    }
    @Override
    public void run(){

    }
}
