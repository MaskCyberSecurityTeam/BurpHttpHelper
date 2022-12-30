package burp.ui.main;

import burp.IBurpExtenderCallbacks;
import burp.bean.Rule;
import burp.constant.ConfigKey;
import burp.constant.RuleActionOption;
import burp.constant.WindowSize;
import burp.ui.component.PlaceholderTextField;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Vector;

@Data
public class MainPanel extends JPanel {

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

    private String configFilePath;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    public static final RuleTable table = new RuleTable();

    public static final String CONFIG_FILE_NAME = "config2.json";

    public MainPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        String pluginJarFilePath = iBurpExtenderCallbacks.getExtensionFilename();
        this.configFilePath = pluginJarFilePath.substring(0, pluginJarFilePath.lastIndexOf(File.separator)) + File.separator + CONFIG_FILE_NAME;

        initComponent();
        initEvent();

        loadConfig();

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(rulePanel, BorderLayout.CENTER);
    }

    private void initComponent() {
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

    private void initEvent() {
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

    private void ruleFormWindow() {
        ruleFormWindow(null);
    }

    private void ruleFormWindow(Rule rule) {
        JFrame formWindow = new JFrame();
        formWindow.setLocationRelativeTo(this);
        formWindow.setSize(WindowSize.RULE_FORM_WINDOW);
        formWindow.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        PlaceholderTextField urlTextField = new PlaceholderTextField();
        PlaceholderTextField headerNameTextField = new PlaceholderTextField();
        PlaceholderTextField headerValueTextField = new PlaceholderTextField();
        JComboBox<RuleActionOption> actionComboBox = new JComboBox<>();
        actionComboBox.setModel(new DefaultComboBoxModel<>(RuleActionOption.values()));
        JButton submitButton = new JButton("提交(Submit)");

        urlTextField.setPlaceholder("https://*mask-sec.com");
        headerNameTextField.setPlaceholder("User-Agent");
        headerValueTextField.setPlaceholder("MaskSecAgent");

        JPanel panel = new JPanel(new MigLayout("", "[][grow]"));
        panel.add(new JLabel("地址(URL): "), "cell 0 0");
        panel.add(urlTextField, "cell 1 0, grow");
        panel.add(new JLabel("协议头(HeaderName): "), "cell 0 1");
        panel.add(headerNameTextField, "cell 1 1, grow");
        panel.add(new JLabel("协议值(HeaderValue): "), "cell 0 2");
        panel.add(headerValueTextField, "cell 1 2, grow");
        panel.add(new JLabel("动作(Action): "), "cell 0 3");
        panel.add(actionComboBox, "cell 1 3, grow, wrap");
        panel.add(submitButton, "span, grow");

        if (rule != null) {
            urlTextField.setText(rule.getUrl());
            headerNameTextField.setText(rule.getHeaderName());
            headerValueTextField.setText(rule.getHeaderValue());
            actionComboBox.setSelectedItem(rule.getAction());
        }

        submitButton.addActionListener(e -> {
            if (rule != null) {
                rule.setUrl(urlTextField.getText());
                rule.setHeaderName(headerNameTextField.getText());
                rule.setHeaderValue(headerValueTextField.getText());
                rule.setAction((RuleActionOption) actionComboBox.getSelectedItem());
                table.updateUI();
            } else {
                Rule newRule = Rule.builder().url(urlTextField.getText()).headerName(headerNameTextField.getText()).headerValue(headerValueTextField.getText()).action((RuleActionOption) actionComboBox.getSelectedItem()).id(table.getRowCount()).build();
                table.addRow(newRule);
            }
            formWindow.dispose();
        });

        formWindow.setContentPane(panel);
        SwingUtilities.invokeLater(() -> formWindow.setVisible(true));
    }

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

    private void loadConfig() {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try {
                JSONObject jsonObject = JSONUtil.readJSONObject(configFile, StandardCharsets.UTF_8);

                JSONObject mainPanelConfig = jsonObject.getJSONObject("mainPanelConfig");
                JSONArray jsonArray = JSONUtil.parseArray(mainPanelConfig.get(ConfigKey.RULE_TABLE_KEY));
                table.addRows(new Vector<>(jsonArray.toList(Rule.class)));

                randomUserAgentCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.RANDOM_UA_KEY));
                repeaterResponseAutoDecodeCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.RP_AD_KEY));
                comparerToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.COMPARER_TOOL_KEY));
                decoderToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.DECODER_TOOL_KEY));
                extenderToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.EXTENDER_TOOL_KEY));
                intruderToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.INTRUDER_TOOL_KEY));
                proxyToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.PROXY_TOOL_KEY));
                repeaterToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.REPEATER_TOOL_KEY));
                scannerToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.SCANNER_TOOL_KEY));
                sequencerToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.SEQUENCER_TOOL_KEY));
                spiderToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.SPIDER_TOOL_KEY));
                suiteToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.SUITE_TOOL_KEY));
                targetToolCheckBox.setSelected(mainPanelConfig.getBool(ConfigKey.TARGET_TOOL_KEY));
            } catch (Exception e) {
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
    }
}