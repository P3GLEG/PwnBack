package burp;

import com.k4ch0w.wayback_machine.PwnBack;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JSplitPane splitPane;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Wayback Machine");
        SwingUtilities.invokeLater(() -> {
            PwnBack p = new PwnBack();
            panel = p.getGui();
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
