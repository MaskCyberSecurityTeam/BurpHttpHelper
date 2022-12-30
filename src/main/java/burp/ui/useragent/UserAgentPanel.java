package burp.ui.useragent;

import burp.IBurpExtenderCallbacks;
import burp.constant.ConfigKey;
import burp.core.UserAgentCore;
import burp.util.FileUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;

@Data
public class UserAgentPanel extends JPanel {

    private JPanel configPanel;

    private JCheckBox pcCheckBox;

    private JCheckBox mobileCheckBox;

    private JTextArea pcTextArea;

    private JTextArea mobileTextArea;

    private JTabbedPane userAgentTabbedPane;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    public static final String CONFIG_FILE_NAME = "config.json";

    public static final String DEFAULT_PC_UA_FILE     = "useragent-pc.txt";
    public static final String DEFAULT_MOBILE_UA_FILE = "useragent-mobile.txt";

    private String configFilePath;

    public UserAgentPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        String pluginJarFilePath = iBurpExtenderCallbacks.getExtensionFilename();
        this.configFilePath = pluginJarFilePath.substring(0, pluginJarFilePath.lastIndexOf(File.separator)) + File.separator + CONFIG_FILE_NAME;

        initComponent();

        boolean loadFlag = loadConfig();

        if (!loadFlag) {
            if (UserAgentCore.pcUserAgent.size() == 0 && "".equals(pcTextArea.getText())) {
                InputStream inputStream = UserAgentCore.class.getClassLoader().getResourceAsStream(DEFAULT_PC_UA_FILE);
                FileUtil.readLines(inputStream, UserAgentCore.pcUserAgent);
            }
            if (UserAgentCore.mobileUserAgent.size() == 0 && "".equals(mobileTextArea.getText())) {
                InputStream inputStream = UserAgentCore.class.getClassLoader().getResourceAsStream(DEFAULT_MOBILE_UA_FILE);
                FileUtil.readLines(inputStream, UserAgentCore.mobileUserAgent);
            }
            initializeUserAgentTextAreaData();
        }
    }

    private void initComponent() {
        configPanel = new JPanel();
        pcTextArea = new JTextArea();
        mobileTextArea = new JTextArea();
        userAgentTabbedPane = new JTabbedPane();

        pcCheckBox = new JCheckBox("电脑(PC)");
        mobileCheckBox = new JCheckBox("手机(Mobile)");
        configPanel.add(pcCheckBox);
        configPanel.add(mobileCheckBox);
        configPanel.setBorder(new TitledBorder("配置启用(ConfigSwitch)"));

        userAgentTabbedPane.addTab("电脑(PC)", new JScrollPane(pcTextArea));
        userAgentTabbedPane.addTab("手机(Mobile)", new JScrollPane(mobileTextArea));

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(userAgentTabbedPane, BorderLayout.CENTER);
    }

    private boolean loadConfig() {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try {
                JSONObject jsonObject = JSONUtil.readJSONObject(configFile, StandardCharsets.UTF_8);
                JSONObject userAgentPanelConfig = jsonObject.getJSONObject("userAgentPanelConfig");

                pcCheckBox.setSelected(userAgentPanelConfig.getBool(ConfigKey.PC_UA_KEY));
                mobileCheckBox.setSelected(userAgentPanelConfig.getBool(ConfigKey.MOBILE_UA_KEY));

                JSONArray pcUAJSONArray = JSONUtil.parseArray(userAgentPanelConfig.get(ConfigKey.PC_UA_LIST_KEY));
                JSONArray mobileUAJSONArray = JSONUtil.parseArray(userAgentPanelConfig.get(ConfigKey.MOBILE_UA_LIST_KEY));
                UserAgentCore.pcUserAgent.addAll(pcUAJSONArray.toList(String.class));
                UserAgentCore.mobileUserAgent.addAll(mobileUAJSONArray.toList(String.class));
                initializeUserAgentTextAreaData();
                return true;
            } catch (Exception e) {
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
        return false;
    }

    private void initializeUserAgentTextAreaData() {
        for (String line : UserAgentCore.mobileUserAgent) {
            mobileTextArea.append(line);
            mobileTextArea.append("\r\n");
        }

        for (String line : UserAgentCore.pcUserAgent) {
            pcTextArea.append(line);
            pcTextArea.append("\r\n");
        }
    }
}