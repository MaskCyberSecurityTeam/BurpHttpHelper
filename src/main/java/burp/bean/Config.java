package burp.bean;

import lombok.Data;

import java.util.HashMap;

@Data
public class Config {

    private final HashMap<String, Object> mainPanelConfig = new HashMap<>();

    private final HashMap<String, Object> userAgentPanelConfig = new HashMap<>();

}