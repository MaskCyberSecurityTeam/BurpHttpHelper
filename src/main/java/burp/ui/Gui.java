package burp.ui;

import burp.IBurpExtenderCallbacks;
import lombok.Data;

import javax.swing.*;

@Data
public class Gui extends JTabbedPane {

    private MainPanel mainPanel;

    private UserAgentPanel userAgentPanel;

    private DropPacketPanel dropPacketPanel;

    public Gui(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.mainPanel = new MainPanel(iBurpExtenderCallbacks);
        this.userAgentPanel = new UserAgentPanel(iBurpExtenderCallbacks);
        this.dropPacketPanel = new DropPacketPanel();

        addTab("主面板", mainPanel);
        addTab("UA面板", userAgentPanel);
        addTab("丢弃数据包面板", dropPacketPanel);
    }
}