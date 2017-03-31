package burp;

import com.k4ch0w.pwnback.PwnBackGUI;
import com.k4ch0w.pwnback.PwnBackMediator;
import com.k4ch0w.pwnback.PwnBackSettings;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PwnBackGUI gui;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("PwnBack");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                PwnBackSettings settings = new PwnBackSettings();
                PwnBackMediator mediator = new PwnBackMediator();
                gui = mediator.getGui();
                callbacks.customizeUiComponent(gui);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "PwnBack";
    }

    @Override
    public Component getUiComponent() {
        return gui;
    }


    //
    // class to hold details of each log entry
    //


}