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

    // 主要的ui
    private Gui gui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        gui = new Gui(iBurpExtenderCallbacks);

        // 注册插件的信息和在插件控制台打印插件信息
        iBurpExtenderCallbacks.setExtensionName(ProjectInfo.EXT_NAME);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.TEAM);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.AUTHOR);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.VERSION_BANNER);
        iBurpExtenderCallbacks.printOutput(ProjectInfo.GITHUB);

        // 注册鼠标右键菜单栏、注册Http监听器
        iBurpExtenderCallbacks.registerContextMenuFactory(new ContextMenuGui(iBurpExtenderCallbacks, gui));
        iBurpExtenderCallbacks.registerHttpListener(new IHttpListenerImpl(iBurpExtenderCallbacks, gui));

        // 将主页面(tab)添加到Burp面板中
        SwingUtilities.invokeLater(() -> iBurpExtenderCallbacks.addSuiteTab(BurpExtender.this));
    }

    /**
     * 在Burp的tab上显示的标题
     *
     * @return 在Burp的tab上显示的标题
     */
    @Override
    public String getTabCaption() {
        return ProjectInfo.TAB_TITLE;
    }

    /**
     * 插件主页面
     *
     * @return 主页面
     */
    @Override
    public Component getUiComponent() {
        return gui;
    }
}
