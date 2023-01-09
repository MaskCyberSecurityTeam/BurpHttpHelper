package burp.ui.rule;

import burp.IBurpExtenderCallbacks;
import burp.bean.Rule;
import burp.constant.ConfigKey;
import burp.constant.RuleActionOption;
import burp.constant.RuleTypeOption;
import burp.constant.WindowSize;
import burp.ui.component.BurpPanel;
import burp.ui.component.PlaceholderTextField;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Vector;

/**
 * 规则面板
 *
 * @author RichardTang
 */
@Data
public class RulePanel extends BurpPanel {

    private JPanel otherPanel;
    private JPanel toolPanel;
    private JPanel configPanel;
    private JPanel rulePanel;

    private JCheckBox randomUserAgentCheckBox;
    private JCheckBox repeaterResponseAutoDecodeCheckBox;

    private JButton addButton;
    private JButton removeButton;
    private JButton modifyButton;

    private JCheckBox comparerToolCheckBox;
    private JCheckBox decoderToolCheckBox;
    private JCheckBox extenderToolCheckBox;
    private JCheckBox intruderToolCheckBox;
    private JCheckBox proxyToolCheckBox;
    private JCheckBox repeaterToolCheckBox;
    private JCheckBox scannerToolCheckBox;
    private JCheckBox sequencerToolCheckBox;
    private JCheckBox spiderToolCheckBox;
    private JCheckBox suiteToolCheckBox;
    private JCheckBox targetToolCheckBox;
    private JPanel    listenerConfigPanel;

    public static final RuleTable table = new RuleTable();

    public RulePanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        super(iBurpExtenderCallbacks);

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(rulePanel, BorderLayout.CENTER);
    }

    public void initComponent() {
        randomUserAgentCheckBox = new JCheckBox("随机UA头(Random UA Header)");
        repeaterResponseAutoDecodeCheckBox = new JCheckBox("RepeaterResponse自动解码(Repeater Response Auto Decode)");
        otherPanel = new JPanel();
        otherPanel.add(randomUserAgentCheckBox);
        otherPanel.add(repeaterResponseAutoDecodeCheckBox);
        otherPanel.setBorder(new TitledBorder("其他配置(OtherConfig)"));

        comparerToolCheckBox = new JCheckBox("对比(Comparer)");
        decoderToolCheckBox = new JCheckBox("编码(Decoder)");
        extenderToolCheckBox = new JCheckBox("插件(Extender)");
        intruderToolCheckBox = new JCheckBox("测试(Intruder)");
        proxyToolCheckBox = new JCheckBox("代理(Proxy)");
        repeaterToolCheckBox = new JCheckBox("重放(Repeater)");
        scannerToolCheckBox = new JCheckBox("扫描(Scanner)");
        sequencerToolCheckBox = new JCheckBox("定序(Sequencer)");
        spiderToolCheckBox = new JCheckBox("爬虫(Spider)");
        suiteToolCheckBox = new JCheckBox("程序(Suite)");
        targetToolCheckBox = new JCheckBox("目标(Target)");

        listenerConfigPanel = new JPanel();
        listenerConfigPanel.add(comparerToolCheckBox);
        listenerConfigPanel.add(decoderToolCheckBox);
        listenerConfigPanel.add(extenderToolCheckBox);
        listenerConfigPanel.add(intruderToolCheckBox);
        listenerConfigPanel.add(proxyToolCheckBox);
        listenerConfigPanel.add(repeaterToolCheckBox);
        listenerConfigPanel.add(scannerToolCheckBox);
        listenerConfigPanel.add(sequencerToolCheckBox);
        listenerConfigPanel.add(spiderToolCheckBox);
        listenerConfigPanel.add(targetToolCheckBox);
        listenerConfigPanel.add(suiteToolCheckBox);
        listenerConfigPanel.setBorder(new TitledBorder("监听配置(ListenerConfig)"));

        toolPanel = new JPanel();
        addButton = new JButton();
        removeButton = new JButton();
        modifyButton = new JButton();

        addButton.setText("添加(Add)");
        removeButton.setText("删除(Remove)");
        modifyButton.setText("修改(Modify)");

        toolPanel.add(addButton);
        toolPanel.add(removeButton);
        toolPanel.add(modifyButton);

        rulePanel = new JPanel();
        rulePanel.setLayout(new BorderLayout());
        rulePanel.setBorder(new TitledBorder("规则管理(RuleManager)"));
        rulePanel.add(toolPanel, BorderLayout.NORTH);
        rulePanel.add(new JScrollPane(table), BorderLayout.CENTER);

        configPanel = new JPanel();
        configPanel.setLayout(new BorderLayout());
        configPanel.add(otherPanel, BorderLayout.NORTH);
        configPanel.add(listenerConfigPanel, BorderLayout.CENTER);
    }

    public void initEvent() {
        addButton.addActionListener(e -> SwingUtilities.invokeLater(this::ruleFormWindow));

        modifyButton.addActionListener(e -> SwingUtilities.invokeLater(() -> {
            Rule rule = table.getSelectedItem();
            if (rule == null) {
                JOptionPane.showMessageDialog(this, "请选择需要修改的数据(Please select row)!");
            } else {
                ruleFormWindow(rule);
            }
        }));

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
        JSONArray jsonArray = JSONUtil.parseArray(rootJSONObject.get(ConfigKey.RULE_TABLE_KEY));
        table.addRows(new Vector<>(jsonArray.toList(Rule.class)));

        randomUserAgentCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.RANDOM_UA_KEY));
        repeaterResponseAutoDecodeCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.RP_AD_KEY));
        comparerToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.COMPARER_TOOL_KEY));
        decoderToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.DECODER_TOOL_KEY));
        extenderToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.EXTENDER_TOOL_KEY));
        intruderToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.INTRUDER_TOOL_KEY));
        proxyToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.PROXY_TOOL_KEY));
        repeaterToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.REPEATER_TOOL_KEY));
        scannerToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.SCANNER_TOOL_KEY));
        sequencerToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.SEQUENCER_TOOL_KEY));
        spiderToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.SPIDER_TOOL_KEY));
        suiteToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.SUITE_TOOL_KEY));
        targetToolCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.TARGET_TOOL_KEY));
    }

    @Override
    public String rootJSONObjectKey() {
        return "rulePanelConfig";
    }

    /**
     * 弹窗，用于添加新规则。
     */
    private void ruleFormWindow() {
        ruleFormWindow(null);
    }

    /**
     * 弹窗，用于回显指定的规则。
     *
     * @param rule 需要回显的规则
     */
    private void ruleFormWindow(Rule rule) {
        JFrame formWindow = new JFrame();
        formWindow.setLocationRelativeTo(this);
        formWindow.setSize(WindowSize.RULE_FORM_WINDOW);
        formWindow.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        PlaceholderTextField urlTextField = new PlaceholderTextField();
        PlaceholderTextField keyNameTextField = new PlaceholderTextField();
        PlaceholderTextField keyValueTextField = new PlaceholderTextField();
        JComboBox<RuleTypeOption> typeComboBox = new JComboBox<>();
        typeComboBox.setModel(new DefaultComboBoxModel<>(RuleTypeOption.values()));
        JComboBox<RuleActionOption> actionComboBox = new JComboBox<>();
        actionComboBox.setModel(new DefaultComboBoxModel<>(RuleActionOption.values()));
        JButton submitButton = new JButton("提交(Submit)");

        // Placeholder文本
        urlTextField.setPlaceholder("https://*mask-sec.com");
        keyNameTextField.setPlaceholder("User-Agent");
        keyValueTextField.setPlaceholder("MaskSecAgent");

        JPanel panel = new JPanel(new MigLayout("", "[][grow]"));
        panel.add(new JLabel("地址(URL): "), "cell 0 0");
        panel.add(urlTextField, "cell 1 0, grow");
        panel.add(new JLabel("键名(KeyName): "), "cell 0 1");
        panel.add(keyNameTextField, "cell 1 1, grow");
        panel.add(new JLabel("键值(KeyValue): "), "cell 0 2");
        panel.add(keyValueTextField, "cell 1 2, grow");
        panel.add(new JLabel("类型(Type): "), "cell 0 3");
        panel.add(typeComboBox, "cell 1 3, grow, wrap");
        panel.add(new JLabel("动作(Action): "), "cell 0 4");
        panel.add(actionComboBox, "cell 1 4, grow, wrap");
        panel.add(submitButton, "span, grow");

        // 清空窗口上一次的数据
        if (rule != null) {
            urlTextField.setText(rule.getUrl());
            keyNameTextField.setText(rule.getKeyName());
            keyValueTextField.setText(rule.getKeyValue());
            typeComboBox.setSelectedItem(rule.getType());
            actionComboBox.setSelectedItem(rule.getAction());
        }

        // 提交
        submitButton.addActionListener(e -> {
            if (rule != null) {
                // 更新规则
                rule.setUrl(urlTextField.getText());
                rule.setKeyName(keyNameTextField.getText());
                rule.setKeyValue(keyValueTextField.getText());
                rule.setType((RuleTypeOption) typeComboBox.getSelectedItem());
                rule.setAction((RuleActionOption) actionComboBox.getSelectedItem());
                table.updateUI();
            } else {
                // 添加新规则到表格中
                Rule newRule = Rule.builder()
                        .url(urlTextField.getText())
                        .keyName(keyNameTextField.getText())
                        .keyValue(keyValueTextField.getText())
                        .type((RuleTypeOption) typeComboBox.getSelectedItem())
                        .action((RuleActionOption) actionComboBox.getSelectedItem())
                        .id(table.getRowCount())
                        .build();
                table.addRow(newRule);
            }
            formWindow.dispose();
        });

        formWindow.setContentPane(panel);
        SwingUtilities.invokeLater(() -> formWindow.setVisible(true));
    }

    /**
     * 校验是否勾选指定的监听模块
     *
     * @param msgType 模块的类型编号
     * @return true:已勾选 false:未勾选
     */
    public boolean validListenerEnabled(int msgType) {
        switch (msgType) {
            case IBurpExtenderCallbacks.TOOL_COMPARER:
                return comparerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_DECODER:
                return decoderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return extenderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return intruderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return proxyToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return repeaterToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return scannerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return sequencerToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return spiderToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_SUITE:
                return suiteToolCheckBox.isSelected();
            case IBurpExtenderCallbacks.TOOL_TARGET:
                return targetToolCheckBox.isSelected();
        }
        return false;
    }
}