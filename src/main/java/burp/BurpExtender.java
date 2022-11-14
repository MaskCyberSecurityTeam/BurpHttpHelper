package burp;

import burp.constant.ProjectInfo;
import burp.listener.IHttpListenerImpl;
import burp.ui.Gui;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender, ITab {

    public static final String TAB_TITLE = "BurpHeaderHelper";

    private Gui gui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        gui = new Gui(iBurpExtenderCallbacks);

        iBurpExtenderCallbacks.setExtensionName(ProjectInfo.EXT_NAME);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.TEAM);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.AUTHOR);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.VERSION_BANNER);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.GITHUB);

        iBurpExtenderCallbacks.registerHttpListener(new IHttpListenerImpl(iBurpExtenderCallbacks, gui));
        SwingUtilities.invokeLater(() -> iBurpExtenderCallbacks.addSuiteTab(BurpExtender.this));
    }

    @Override
    public String getTabCaption() {
        return TAB_TITLE;
    }

    @Override
    public Component getUiComponent() {
        return gui;
    }
}
