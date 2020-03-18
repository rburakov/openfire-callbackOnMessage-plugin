package com.artistsoft;

import org.jivesoftware.openfire.PresenceManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.io.File;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallbackOnMessage implements Plugin, PacketInterceptor {

    private static final Logger Log = LoggerFactory.getLogger(CallbackOnMessage.class);

    private static final String PROPERTY_DEBUG = "plugin.callback_on_message.debug";
    private static final String PROPERTY_URL = "plugin.callback_on_message.url";
    private static final String PROPERTY_TOKEN = "plugin.callback_on_message.token";
    private static final String PROPERTY_SEND_BODY = "plugin.callback_on_message.send_body";
    private static final String PROPERTY_USER_STATUS = "plugin.callback_on_message.user_status";
    private static final String STATUS_BOTH = "Both";
    private static final String STATUS_ONLINE = "Online";
    private static final String STATUS_OFFLINE = "Offline";
    private static final String PROPERTY_USER_REGEX = "plugin.callback_on_message.user_regex";

    private boolean debug;
    private boolean sendBody;

    private String url;
    private String token;
    private String status;
    private String regex;
    private InterceptorManager interceptorManager;
    private UserManager userManager;
    private PresenceManager presenceManager;
    private Client client;

    public void initializePlugin(PluginManager pManager, File pluginDirectory) {
        debug = JiveGlobals.getBooleanProperty(PROPERTY_DEBUG, false);
        sendBody = JiveGlobals.getBooleanProperty(PROPERTY_SEND_BODY, true);
        url = getProperty(PROPERTY_URL, "http://localhost:8080/user/message/callback/url");
        token = getProperty(PROPERTY_TOKEN, UUID.randomUUID().toString());
        status = getProperty(PROPERTY_USER_STATUS, STATUS_BOTH);
        regex = getProperty(PROPERTY_USER_REGEX, null);

        if (debug) {
            Log.debug("initialize CallbackOnMessage plugin. Start.");
            Log.debug("Loaded properties: \nurl={}, \ntoken={}, \nsendBody={}", new Object[]{url, token, sendBody});
        }

        interceptorManager = InterceptorManager.getInstance();
        presenceManager = XMPPServer.getInstance().getPresenceManager();
        userManager = XMPPServer.getInstance().getUserManager();
        client = ClientBuilder.newClient();

        // register with interceptor manager
        interceptorManager.addInterceptor(this);

        if (debug) {
            Log.debug("initialize CallbackOnMessage plugin. Finish.");
        }
    }

    private String getProperty(String code, String defaultSetValue) {
        String value = JiveGlobals.getProperty(code, null);
        if (value == null || value.length() == 0) {
            JiveGlobals.setProperty(code, defaultSetValue);
            value = defaultSetValue;
        }

        return value;
    }

    public void destroyPlugin() {
        // unregister with interceptor manager
        interceptorManager.removeInterceptor(this);
        if (debug) {
            Log.debug("destroy CallbackOnMessage plugin.");
        }
    }


    public void interceptPacket(Packet packet, Session session, boolean incoming,
                                boolean processed) throws PacketRejectedException {
        if (processed
                && incoming
                && packet instanceof Message
                && packet.getTo() != null) {

            Message msg = (Message) packet;
            JID to = packet.getTo();

            if (msg.getType() != Message.Type.chat) {
                return;
            }

            try {
                User userTo = userManager.getUser(to.getNode());
                String usernameTo = userTo.getUsername();

                if (regex != null){
                    Pattern pattern = Pattern.compile(regex);
                    Matcher matcher = pattern.matcher(usernameTo);
                    boolean matches = matcher.matches();

                    if (debug) {
                        Log.debug("matching recipient user {} with regex {}, matches {}", new Object[]{usernameTo, regex, matches});
                    }

                    if (!matches){
                        return;
                    }
                }

                boolean available = presenceManager.isAvailable(userTo);

                if (debug) {
                    Log.debug("intercepted message from {} to {}, recipient is available {}", new Object[]{packet.getFrom().toBareJID(), to.toBareJID(), available});
                }

                if (status.equals(STATUS_BOTH) || (status.equals(STATUS_OFFLINE) && !available) || (status.equals(STATUS_ONLINE) && available)) {
                    JID from = packet.getFrom();
                    String body = sendBody ? msg.getBody() : null;

                    WebTarget target = client.target(url);

                    if (debug) {
                        Log.debug("sending request to url='{}'", target);
                    }

                    MessageData data = new MessageData(token, from.toBareJID(), to.toBareJID(), body);

                    Future<Response> responseFuture = target
                            .request()
                            .async()
                            .post(Entity.json(data));

                    if (debug) {
                        try {
                            Response response = responseFuture.get();
                            Log.debug("got response status url='{}' status='{}'", target, response.getStatus());
                        } catch (Exception e) {
                            Log.debug("can't get response status url='{}'", target, e);
                        }
                    }
                }
            } catch (UserNotFoundException e) {
                if (debug) {
                    Log.debug("can't find user with name: " + to.getNode());
                }
            }
        }
    }

}
