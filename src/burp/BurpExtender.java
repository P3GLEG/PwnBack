package burp;

import com.k4ch0w.pwnback.PwnBackGUI;
import com.k4ch0w.pwnback.PwnBackMediator;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PwnBackGUI panel;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Wayback Machine");
        SwingUtilities.invokeLater(() -> {
            PwnBackMediator mediator = new PwnBackMediator();
            panel = mediator.getGui();
            callbacks.customizeUiComponent(panel);
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "Wayback Machine";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

}
