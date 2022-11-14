package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.bean.Rule;
import burp.constant.ConfigKey;
import burp.constant.RuleActionOption;
import burp.constant.WindowSize;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Vector;

public class Gui extends JPanel {

    private JButton addButton;
    private JButton removeButton;
    private JButton modifyButton;
    private JButton saveButton;

    private JPanel      centerPanel;
    private JPanel      toolPanel;
    private JScrollPane tableScrollPanel;

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

    public static final String CONFIG_FILE_NAME = "config.json";

    public Gui() {
        initComponent();
        initEvent();

        loadConfig();

        setLayout(new BorderLayout());
        add(listenerConfigPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
    }

    public Gui(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        String pluginJarFilePath = iBurpExtenderCallbacks.getExtensionFilename();
        this.configFilePath = pluginJarFilePath.substring(0, pluginJarFilePath.lastIndexOf(File.separator)) + File.separator + CONFIG_FILE_NAME;

        initComponent();
        initEvent();

        loadConfig();

        setLayout(new BorderLayout());
        add(listenerConfigPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
    }

    private void initComponent() {
        listenerConfigPanel = new JPanel();
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
        saveButton = new JButton();

        addButton.setText("添加(Add)");
        removeButton.setText("删除(Remove)");
        modifyButton.setText("修改(Modify)");
        saveButton.setText("保存(Save)");

        toolPanel.add(addButton);
        toolPanel.add(removeButton);
        toolPanel.add(modifyButton);
        toolPanel.add(saveButton);

        tableScrollPanel = new JScrollPane(table);

        centerPanel = new JPanel();
        centerPanel.setLayout(new BorderLayout());
        centerPanel.setBorder(new TitledBorder("规则管理(RuleManager)"));
        centerPanel.add(toolPanel, BorderLayout.NORTH);
        centerPanel.add(tableScrollPanel, BorderLayout.CENTER);
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

        saveButton.addActionListener(e -> {
            HashMap<String, Object> config = new HashMap<>();
            config.put(ConfigKey.RULE_TABLE_KEY, table.getRuleData());
            config.put(ConfigKey.COMPARER_TOOL_KEY, comparerToolCheckBox.isSelected());
            config.put(ConfigKey.DECODER_TOOL_KEY, decoderToolCheckBox.isSelected());
            config.put(ConfigKey.EXTENDER_TOOL_KEY, extenderToolCheckBox.isSelected());
            config.put(ConfigKey.INTRUDER_TOOL_KEY, intruderToolCheckBox.isSelected());
            config.put(ConfigKey.PROXY_TOOL_KEY, proxyToolCheckBox.isSelected());
            config.put(ConfigKey.REPEATER_TOOL_KEY, repeaterToolCheckBox.isSelected());
            config.put(ConfigKey.SCANNER_TOOL_KEY, scannerToolCheckBox.isSelected());
            config.put(ConfigKey.SEQUENCER_TOOL_KEY, sequencerToolCheckBox.isSelected());
            config.put(ConfigKey.SPIDER_TOOL_KEY, spiderToolCheckBox.isSelected());
            config.put(ConfigKey.SUITE_TOOL_KEY, suiteToolCheckBox.isSelected());
            config.put(ConfigKey.TARGET_TOOL_KEY, targetToolCheckBox.isSelected());
            String configJson = JSONUtil.toJsonStr(config);

            try (FileWriter fileWriter = new FileWriter(configFilePath)) {
                fileWriter.write(configJson);
                fileWriter.flush();
                JOptionPane.showMessageDialog(this, "保存成功(Save Success)!", "提示(Tip)", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception exception) {
                JOptionPane.showMessageDialog(this, "配置文件保存失败(Config File Save Fail!)", "提示(Tip)", JOptionPane.WARNING_MESSAGE);
                iBurpExtenderCallbacks.printOutput("配置文件保存失败(Config File Save Fail!)");
                iBurpExtenderCallbacks.printOutput(exception.getMessage());
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

                JSONArray jsonArray = JSONUtil.parseArray(jsonObject.get(ConfigKey.RULE_TABLE_KEY));
                table.addRows(new Vector<>(jsonArray.toList(Rule.class)));

                comparerToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.COMPARER_TOOL_KEY)
                );
                decoderToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.DECODER_TOOL_KEY)
                );
                extenderToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.EXTENDER_TOOL_KEY)
                );
                intruderToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.INTRUDER_TOOL_KEY)
                );
                proxyToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.PROXY_TOOL_KEY)
                );
                repeaterToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.REPEATER_TOOL_KEY)
                );
                scannerToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.SCANNER_TOOL_KEY)
                );
                sequencerToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.SEQUENCER_TOOL_KEY)
                );
                spiderToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.SPIDER_TOOL_KEY)
                );
                suiteToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.SUITE_TOOL_KEY)
                );
                targetToolCheckBox.setSelected(
                        jsonObject.getBool(ConfigKey.TARGET_TOOL_KEY)
                );
            } catch (Exception e) {
                iBurpExtenderCallbacks.issueAlert("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        Gui gui = new Gui();

        JFrame jFrame = new JFrame();
        jFrame.setContentPane(gui);
        jFrame.setSize(WindowSize.LOCAL_MAIN_WINDOW);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        SwingUtilities.invokeLater(() -> jFrame.setVisible(true));
    }
}