package burp;

import com.k4ch0w.pwnback.PwnBackGUI;
import com.k4ch0w.pwnback.PwnBackMediator;
import com.k4ch0w.pwnback.PwnBackSettings;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PwnBackGUI panel;
    // private DocumentFrame d;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("PwnBack");
        SwingUtilities.invokeLater(() -> {
            PwnBackSettings settings = new PwnBackSettings(); //Singleton Initialization
            PwnBackMediator mediator = new PwnBackMediator();
            panel = mediator.getGui();
            callbacks.customizeUiComponent(panel);

            /*
            try {
                ArrayList<String> temp = new ArrayList<String>();
                temp.add("fuckit");

                d = new DocumentFrame(temp, "<html>Ain't no way I'mma fail </html>");
            } catch (IOException e) {
                e.printStackTrace();
            } catch (SAXException e) {
                e.printStackTrace();
            }
            callbacks.customizeUiComponent(d);

            */
            callbacks.addSuiteTab(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "PwnBack";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

}