package burp.ui.useragent;

import burp.IBurpExtenderCallbacks;
import burp.constant.ConfigKey;
import burp.core.UserAgentCore;
import burp.ui.component.BurpPanel;
import burp.util.FileUtil;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;

@Data
public class UserAgentPanel extends BurpPanel {

    private JPanel      configPanel;
    private JCheckBox   pcCheckBox;
    private JCheckBox   mobileCheckBox;
    private JTextArea   pcTextArea;
    private JTextArea   mobileTextArea;
    private JTabbedPane userAgentTabbedPane;

    public static final String DEFAULT_PC_UA_FILE     = "useragent-pc.txt";
    public static final String DEFAULT_MOBILE_UA_FILE = "useragent-mobile.txt";

    public UserAgentPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        super(iBurpExtenderCallbacks);

        if (UserAgentCore.pcUserAgent.size() == 0 && "".equals(pcTextArea.getText())) {
            InputStream inputStream = UserAgentCore.class.getClassLoader().getResourceAsStream(DEFAULT_PC_UA_FILE);
            FileUtil.readLines(inputStream, UserAgentCore.pcUserAgent);
        }
        if (UserAgentCore.mobileUserAgent.size() == 0 && "".equals(mobileTextArea.getText())) {
            InputStream inputStream = UserAgentCore.class.getClassLoader().getResourceAsStream(DEFAULT_MOBILE_UA_FILE);
            FileUtil.readLines(inputStream, UserAgentCore.mobileUserAgent);
        }
        for (String line : UserAgentCore.pcUserAgent) {
            pcTextArea.append(line);
            pcTextArea.append("\r\n");
        }
        for (String line : UserAgentCore.mobileUserAgent) {
            mobileTextArea.append(line);
            mobileTextArea.append("\r\n");
        }
    }

    public void initComponent() {
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

    @Override
    public void initEvent() {

    }

    @Override
    public void initConfig(JSONObject rootJSONObject) {
        pcCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.PC_UA_KEY));
        mobileCheckBox.setSelected(rootJSONObject.getBool(ConfigKey.MOBILE_UA_KEY));

        JSONArray pcUAJSONArray = JSONUtil.parseArray(rootJSONObject.get(ConfigKey.PC_UA_LIST_KEY));
        JSONArray mobileUAJSONArray = JSONUtil.parseArray(rootJSONObject.get(ConfigKey.MOBILE_UA_LIST_KEY));

        UserAgentCore.pcUserAgent.addAll(pcUAJSONArray.toList(String.class));
        UserAgentCore.mobileUserAgent.addAll(mobileUAJSONArray.toList(String.class));
    }

    @Override
    public String rootJSONObjectKey() {
        return "userAgentPanelConfig";
    }
}