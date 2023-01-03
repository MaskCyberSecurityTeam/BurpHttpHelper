package burp.listener;

import burp.*;
import burp.core.AutoDecodeCore;
import burp.core.RuleCore;
import burp.core.UserAgentCore;
import burp.Gui;

import java.util.*;

/**
 * Http协议监听器，所有Http请求都会经过该类进行处理。
 *
 * @author RichardTang
 */
public class IHttpListenerImpl implements IHttpListener {

    private Gui gui;

    private IExtensionHelpers helpers;

    private IBurpExtenderCallbacks iBurpExtenderCallbacks;

    public IHttpListenerImpl(IBurpExtenderCallbacks iBurpExtenderCallbacks, Gui gui) {
        this.helpers = iBurpExtenderCallbacks.getHelpers();
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        this.gui = gui;
    }

    @Override
    public void processHttpMessage(int msgType, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {

        // request
        if (messageIsRequest) {
            byte[] requestByte = iHttpRequestResponse.getRequest();
            IRequestInfo iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), requestByte);

            // 判断该数据包是否需要丢弃
            boolean flag = gui.getDropPacketPanel().filterUrlOnData(iRequestInfo.getUrl());
            if (flag && msgType != IBurpExtenderCallbacks.TOOL_REPEATER) {
                // 丢弃该请求
                iHttpRequestResponse.setRequest(new byte[0]);
                return;
            }

            // 匹配规则面板中监听的模块
            if (gui.getRulePanel().validListenerEnabled(msgType)) {
                byte[] body = Arrays.copyOfRange(requestByte, iRequestInfo.getBodyOffset(), requestByte.length);
                List<String> headers = iRequestInfo.getHeaders();

                // 处理UserAgent
                if (gui.getRulePanel().getRandomUserAgentCheckBox().isSelected()) {
                    UserAgentCore.assembly(headers, gui);
                }
                // 处理Header规则
                RuleCore.assembly(headers, iRequestInfo.getUrl());

                // 构造新请求
                byte[] newReq = helpers.buildHttpMessage(headers, body);
                iHttpRequestResponse.setRequest(newReq);
            }
        }
        // response
        else if (gui.getRulePanel().getRepeaterResponseAutoDecodeCheckBox().isSelected() && msgType == IBurpExtenderCallbacks.TOOL_REPEATER) {
            byte[] responseByte = iHttpRequestResponse.getResponse();
            IResponseInfo iResponseInfo = helpers.analyzeResponse(responseByte);

            // 获取body
            byte[] body = Arrays.copyOfRange(responseByte, iResponseInfo.getBodyOffset(), responseByte.length);
            // 进行解码，获取新body
            byte[] newBody = AutoDecodeCore.assembly(new String(body)).getBytes();

            // 旧body和新body，代表没有进行解码操作。
            if (newBody.length != body.length) {
                // 进行了解码操作，重新设置响应给客户端的response。
                iHttpRequestResponse.setResponse(helpers.buildHttpMessage(iResponseInfo.getHeaders(), newBody));
            }
        }
    }
}