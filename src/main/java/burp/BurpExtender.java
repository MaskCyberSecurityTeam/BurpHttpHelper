package burp;

import burp.constant.ProjectInfo;
import burp.listener.IHttpListenerImpl;
import burp.ui.ContextMenuGui;

import javax.swing.*;
import java.awt.*;

/**
 * Burpsuite插件主入口
 *
 * @author RichardTang
 */
public class BurpExtender implements IBurpExtender, ITab {

    private Gui gui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        gui = new Gui(iBurpExtenderCallbacks);

        iBurpExtenderCallbacks.setExtensionName(ProjectInfo.EXT_NAME);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.TEAM);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.AUTHOR);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.VERSION_BANNER);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.GITHUB);

        iBurpExtenderCallbacks.registerContextMenuFactory(new ContextMenuGui(iBurpExtenderCallbacks, gui));
        iBurpExtenderCallbacks.registerHttpListener(new IHttpListenerImpl(iBurpExtenderCallbacks, gui));

        SwingUtilities.invokeLater(() -> iBurpExtenderCallbacks.addSuiteTab(BurpExtender.this));
    }

    @Override
    public String getTabCaption() {
        return ProjectInfo.TAB_TITLE;
    }

    @Override
    public Component getUiComponent() {
        return gui;
    }
}
