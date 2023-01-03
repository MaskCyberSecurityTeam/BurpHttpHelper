package burp.ui.droppacket;

import burp.IBurpExtenderCallbacks;
import burp.ui.component.BurpPanel;
import cn.hutool.json.JSONObject;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.net.URL;

/**
 * 丢弃数据包面板
 *
 * @author RichardTang
 */
public class DropPacketPanel extends BurpPanel {

    private JPanel configPanel;

    private DropPacketTable table;

    private JButton removeButton;

    public DropPacketPanel(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        super(iBurpExtenderCallbacks);

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        setBorder(new TitledBorder("规则管理(RuleManager)"));
    }

    public void initComponent() {
        this.configPanel = new JPanel();
        this.table = new DropPacketTable();

        this.removeButton = new JButton("删除(Remove)");
        this.configPanel.add(this.removeButton);
    }

    public void initEvent() {
        removeButton.addActionListener(e -> {
            int index = table.getSelectedRow();
            if (index != -1) {
                table.removeSelectedItem();
            } else {
                JOptionPane.showMessageDialog(this, "请选择需要删除的数据(Please select row)!");
            }
        });
    }

    @Override
    public void initConfig(JSONObject rootJSONObject) {

    }

    @Override
    public String rootJSONObjectKey() {
        return null;
    }

    /**
     * 根据URL在tableData中搜索是否存在这个URL数据
     *
     * @return true:存在 false:不存在
     */
    public boolean filterUrlOnData(URL url) {
        String targetUrl = url.toExternalForm();
        long count = table.getTableData().stream().filter(i -> targetUrl.contains(i.getUrl())).count();
        return count > 0;
    }

    public DropPacketTable getTable() {
        return table;
    }
}