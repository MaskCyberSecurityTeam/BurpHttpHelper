package burp.ui;

import burp.IBurpExtenderCallbacks;
import lombok.Data;

import javax.swing.*;

@Data
public class Gui extends JTabbedPane {

    private MainPanel mainPanel;

    private UserAgentPanel userAgentPanel;

    public Gui(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.mainPanel = new MainPanel(iBurpExtenderCallbacks);
        this.userAgentPanel = new UserAgentPanel(iBurpExtenderCallbacks);

        addTab("主面板", mainPanel);
        addTab("UA面板", userAgentPanel);
    }
}