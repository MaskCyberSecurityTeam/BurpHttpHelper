package burp.ui;

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
import java.util.List;

@Data
public class UserAgentPanel extends JPanel {

    private JPanel configPanel;

    private JCheckBox pcCheckBox;

    private JCheckBox mobileCheckBox;

    private JButton saveButton;

    private JTextArea pcTextArea;

    private JTextArea mobileTextArea;

    private JTabbedPane userAgentTabbedPane;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    public static final String CONFIG_FILE_NAME = "useragent.json";

    public static final String DEFAULT_PC_UA_FILE     = "useragent-pc.txt";
    public static final String DEFAULT_MOBILE_UA_FILE = "useragent-mobile.txt";

    private String configFilePath;

    public UserAgentPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        String pluginJarFilePath = iBurpExtenderCallbacks.getExtensionFilename();
        this.configFilePath = pluginJarFilePath.substring(0, pluginJarFilePath.lastIndexOf(File.separator)) + File.separator + CONFIG_FILE_NAME;

        initComponent();
        initEvent();

        loadConfig();

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

    private void initComponent() {
        configPanel = new JPanel();
        pcTextArea = new JTextArea();
        mobileTextArea = new JTextArea();
        userAgentTabbedPane = new JTabbedPane();

        saveButton = new JButton("保存(Save)");
        pcCheckBox = new JCheckBox("电脑(PC)");
        mobileCheckBox = new JCheckBox("手机(Mobile)");
        configPanel.add(pcCheckBox);
        configPanel.add(mobileCheckBox);
        configPanel.add(saveButton);
        configPanel.setBorder(new TitledBorder("配置启用(ConfigSwitch)"));

        userAgentTabbedPane.addTab("电脑(PC)", pcTextArea);
        userAgentTabbedPane.addTab("手机(Mobile)", mobileTextArea);

        setLayout(new BorderLayout());
        add(configPanel, BorderLayout.NORTH);
        add(userAgentTabbedPane, BorderLayout.CENTER);
    }

    private void initEvent() {
        saveButton.addActionListener(e -> {
            String pcTextAreaText = pcTextArea.getText();
            UserAgentCore.pcUserAgent.clear();
            UserAgentCore.pcUserAgent.addAll(Arrays.asList(pcTextAreaText.split("\n")));

            String mobileTextAreaText = mobileTextArea.getText();
            UserAgentCore.mobileUserAgent.clear();
            UserAgentCore.mobileUserAgent.addAll(Arrays.asList(mobileTextAreaText.split("\n")));

            HashMap<String, Object> config = new HashMap<>();
            config.put(ConfigKey.PC_UA_KEY, pcCheckBox.isSelected());
            config.put(ConfigKey.MOBILE_UA_KEY, mobileCheckBox.isSelected());
            config.put(ConfigKey.PC_UA_LIST_KEY, UserAgentCore.pcUserAgent);
            config.put(ConfigKey.MOBILE_UA_LIST_KEY, UserAgentCore.mobileUserAgent);
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

    private void loadConfig() {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try {
                JSONObject jsonObject = JSONUtil.readJSONObject(configFile, StandardCharsets.UTF_8);
                pcCheckBox.setSelected(jsonObject.getBool(ConfigKey.PC_UA_KEY));
                mobileCheckBox.setSelected(jsonObject.getBool(ConfigKey.MOBILE_UA_KEY));

                JSONArray pcUAJSONArray = JSONUtil.parseArray(jsonObject.get(ConfigKey.PC_UA_LIST_KEY));
                JSONArray mobileUAJSONArray = JSONUtil.parseArray(jsonObject.get(ConfigKey.MOBILE_UA_LIST_KEY));
                UserAgentCore.pcUserAgent.addAll(pcUAJSONArray.toList(String.class));
                UserAgentCore.mobileUserAgent.addAll(mobileUAJSONArray.toList(String.class));
                initializeUserAgentTextAreaData();
            } catch (Exception e) {
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
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