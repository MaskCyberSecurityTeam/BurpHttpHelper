package burp.listener;

import burp.*;
import burp.core.AutoDecodeCore;
import burp.core.RuleCore;
import burp.core.UserAgentCore;
import burp.ui.Gui;

import java.util.*;

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
        if (messageIsRequest) {
            byte[] requestByte = iHttpRequestResponse.getRequest();
            IRequestInfo iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse.getHttpService(), requestByte);

            boolean flag = gui.getDropPacketPanel().filterUrlOnData(iRequestInfo.getUrl());
            if (flag && msgType != IBurpExtenderCallbacks.TOOL_REPEATER) {
                iHttpRequestResponse.setRequest(new byte[0]);
                return;
            }

            if (gui.getMainPanel().validListenerEnabled(msgType)) {
                byte[] body = Arrays.copyOfRange(requestByte, iRequestInfo.getBodyOffset(), requestByte.length);
                List<String> headers = iRequestInfo.getHeaders();

                if (gui.getMainPanel().getRandomUserAgentCheckBox().isSelected()) {
                    UserAgentCore.assembly(headers, gui);
                }
                RuleCore.assembly(headers, iRequestInfo.getUrl());

                byte[] newReq = helpers.buildHttpMessage(headers, body);
                iHttpRequestResponse.setRequest(newReq);
            }
        } else if (gui.getMainPanel().getRepeaterResponseAutoDecodeCheckBox().isSelected() && msgType == IBurpExtenderCallbacks.TOOL_REPEATER) {
            byte[] responseByte = iHttpRequestResponse.getResponse();
            IResponseInfo iResponseInfo = helpers.analyzeResponse(responseByte);

            byte[] body = Arrays.copyOfRange(responseByte, iResponseInfo.getBodyOffset(), responseByte.length);
            byte[] newBody = AutoDecodeCore.assembly(new String(body)).getBytes();

            if (newBody.length != body.length) {
                iHttpRequestResponse.setResponse(helpers.buildHttpMessage(iResponseInfo.getHeaders(), newBody));
            }
        }
    }
}