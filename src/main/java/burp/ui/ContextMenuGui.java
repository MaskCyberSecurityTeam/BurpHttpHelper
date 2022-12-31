package burp.ui;

import burp.*;
import burp.bean.Drop;
import burp.util.URLUtil;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

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
        JMenuItem dropPacketMenuItem = new JMenuItem("丢弃该数据包");
        dropPacketMenuItem.addActionListener(e -> {
            IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
            IRequestInfo iRequestInfo = iBurpExtenderCallbacks.getHelpers().analyzeRequest(iReqResp.getHttpService(), iReqResp.getRequest());
            URL url = iRequestInfo.getUrl();
            String URIPath = URLUtil.getURIPath(url.toExternalForm());
            Drop drop = Drop.builder().id(gui.getDropPacketPanel().getTable().getDataSize()).url(URIPath).comment("").build();
            gui.getDropPacketPanel().getTable().addRow(drop);
        });
        menuItems.add(dropPacketMenuItem);
        return menuItems;
    }
}
