package burp;

import com.k4ch0w.pwnback.PwnBackMediator;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Custom logger");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                PwnBackMediator mediator = new PwnBackMediator();

                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

                JScrollPane scrollPane = new JScrollPane(mediator.getGui().getLogTable());
                JButton startBtn = new JButton();
                startBtn.addActionListener(new ActionListener()
                {
                    public void actionPerformed(ActionEvent e)
                    {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {

                                mediator.start();
                            }
                        });
                    }
                });
                splitPane.setLeftComponent(scrollPane);
                splitPane.setRightComponent(startBtn);

                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(scrollPane);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "Logger";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }


    //
    // class to hold details of each log entry
    //


}