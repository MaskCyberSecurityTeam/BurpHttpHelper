package burp.ui.component;

import burp.IBurpExtenderCallbacks;
import burp.constant.ConfigKey;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import javax.swing.*;
import java.io.File;
import java.nio.charset.StandardCharsets;

public abstract class BurpPanel extends JPanel {

    // 配置文件绝对路径
    private String configFilePath;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    protected BurpPanel() {

    }

    public BurpPanel(final IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;

        // 根据Jar包加载的位置获取配置文件的绝对路径
        String pluginJarFilePath = iBurpExtenderCallbacks.getExtensionFilename();
        this.configFilePath = pluginJarFilePath.substring(0, pluginJarFilePath.lastIndexOf(File.separator)) + File.separator + ConfigKey.CONFIG_FILE_NAME;

        // 初始化动作
        initComponent();
        initEvent();
        loadConfigFile();
    }

    public abstract void initComponent();

    public abstract void initEvent();

    public abstract void initConfig(JSONObject rootJSONObject);

    public abstract String rootJSONObjectKey();

    public void loadConfigFile() {
        File configFile = new File(configFilePath);
        if (configFile.exists()) {
            try {
                String rootKey = rootJSONObjectKey();
                if (rootKey == null) {
                    return;
                } else {
                    JSONObject rootJSONObject = JSONUtil.readJSONObject(configFile, StandardCharsets.UTF_8).getJSONObject(rootKey);
                    initConfig(rootJSONObject);
                }
            } catch (Exception e) {
                iBurpExtenderCallbacks.printOutput("配置文件读取失败(Config File Read Fail!)");
                iBurpExtenderCallbacks.printOutput(e.getMessage());
            }
        }
    }
}