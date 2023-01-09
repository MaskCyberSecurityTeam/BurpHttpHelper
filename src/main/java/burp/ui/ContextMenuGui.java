package burp.ui;

import burp.*;
import burp.bean.Drop;
import burp.constant.ProjectInfo;
import burp.util.URLUtil;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Burp中邮件的菜单选项
 *
 * @author RichardTang
 */
public class ContextMenuGui implements IContextMenuFactory {

    private Gui gui;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    public ContextMenuGui(final IBurpExtenderCallbacks iBurpExtenderCallbacks, final Gui gui) {
        this.gui = gui;
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menuItems = new ArrayList<JMenuItem>();
        JMenu burpHttpHelperMenu = new JMenu(ProjectInfo.TAB_TITLE);
        JMenuItem dropPacketMenuItem = new JMenuItem("丢弃该数据包");
        // 当用户点击右键时，将请求的信息发送到丢弃数据包的面板中
        dropPacketMenuItem.addActionListener(e -> {
            IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
            IRequestInfo iRequestInfo = iBurpExtenderCallbacks.getHelpers().analyzeRequest(iReqResp.getHttpService(), iReqResp.getRequest());
            String URIPath = URLUtil.getURIPath(iRequestInfo.getUrl().toExternalForm());
            Drop drop = Drop.builder().id(gui.getDropPacketPanel().getTable().getDataSize()).url(URIPath).comment("").build();
            gui.getDropPacketPanel().getTable().addRow(drop);
        });
        burpHttpHelperMenu.add(dropPacketMenuItem);
        menuItems.add(burpHttpHelperMenu);
        return menuItems;
    }
}
