package burp.listener;

import burp.*;
import burp.core.RuleCore;
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
        if (messageIsRequest && gui.validListenerEnabled(msgType)) {

            byte[] requestByte = iHttpRequestResponse.getRequest();

            IRequestInfo iRequestInfo = helpers.analyzeRequest(
                    iHttpRequestResponse.getHttpService(),
                    requestByte
            );

            byte[] body = Arrays.copyOfRange(requestByte, iRequestInfo.getBodyOffset(), requestByte.length);

            List<String> headers = iRequestInfo.getHeaders();
            RuleCore.assembly(headers, iRequestInfo.getUrl());

            byte[] newReq = helpers.buildHttpMessage(headers, body);
            iHttpRequestResponse.setRequest(newReq);
        }
    }
}