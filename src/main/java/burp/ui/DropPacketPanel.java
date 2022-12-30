package burp.ui;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.net.URL;

public class DropPacketPanel extends JPanel {

    private JPanel configPanel;

    private DropPacketTable table;

    private JButton saveButton;

    private JButton removeButton;

    public DropPacketPanel() {
        initComponent();
        initEvent();

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        setBorder(new TitledBorder("规则管理(RuleManager)"));
    }

    private void initComponent() {
        this.configPanel = new JPanel();
        this.table = new DropPacketTable();

        this.saveButton = new JButton("保存(Save)");
        this.removeButton = new JButton("删除(Remove)");

        this.configPanel.add(this.removeButton);
        this.configPanel.add(this.saveButton);
    }

    private void initEvent() {
        removeButton.addActionListener(e -> {
            int index = table.getSelectedRow();
            if (index != -1) {
                table.removeSelectedItem();
            } else {
                JOptionPane.showMessageDialog(this, "请选择需要删除的数据(Please select row)!");
            }
        });
    }

    public boolean filterUrlOnData(URL url) {
        String targetUrl = url.toExternalForm();
        long count = table.getDropPacketData().stream().filter(i -> targetUrl.contains(i.getUrl())).count();
        return count > 0;
    }

    public DropPacketTable getTable() {
        return table;
    }
}