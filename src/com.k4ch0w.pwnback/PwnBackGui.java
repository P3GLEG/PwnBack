package com.k4ch0w.pwnback;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

public class PwnBackGui {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PwnBackGui(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers){
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

}