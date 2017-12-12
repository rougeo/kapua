/*******************************************************************************
 * Copyright (c) 2017 Eurotech and/or its affiliates and others
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Eurotech - initial API and implementation
 *******************************************************************************/
package org.eclipse.kapua.broker.core.plugin;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

import org.apache.activemq.command.ConnectionInfo;
import org.eclipse.kapua.model.id.KapuaId;
import org.eclipse.kapua.service.authentication.KapuaPrincipal;
import org.eclipse.kapua.service.authentication.token.AccessToken;
import org.eclipse.kapua.service.device.registry.connection.DeviceConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Connection information container
 * 
 * @since 1.0
 */
public class KapuaConnectionContext {

    protected final static Logger logger = LoggerFactory.getLogger(KapuaConnectionContext.class);

    private String brokerId;
    private KapuaPrincipal principal;
    private String userName;
    private KapuaId scopeId;
    private KapuaId userId;
    private String accountName;
    private String clientId;
    private String fullClientId;
    private String clientIp;
    private String connectionId;
    private String oldConnectionId;
    private KapuaId kapuaConnectionId;
    private ConnectorDescriptor connectorDescriptor;
    private boolean[] hasPermissions;
    private String brokerIpOrHostName;

    // use to track the allowed destinations for debug purpose
    private List<String> authDestinations;

    public KapuaConnectionContext(Long scopeId, String clientId) {
        authDestinations = new ArrayList<>();
        this.clientId = clientId;
        updateFullClientId(scopeId);
    }

    public KapuaConnectionContext(String brokerId, ConnectionInfo info) {
        authDestinations = new ArrayList<>();
        this.brokerId = brokerId;
        userName = info.getUserName();
        clientId = info.getClientId();
        clientIp = info.getClientIp();
        connectionId = info.getConnectionId().getValue();
    }

    public KapuaConnectionContext(String brokerId, KapuaPrincipal kapuaPrincipal, ConnectionInfo info) {
        authDestinations = new ArrayList<>();
        this.brokerId = brokerId;
        userName = info.getUserName();
        clientId = kapuaPrincipal.getClientId();
        scopeId = kapuaPrincipal.getAccountId();
        clientIp = info.getClientIp();
        connectionId = info.getConnectionId().getValue();
        updateFullClientId();
    }

    public void update(AccessToken accessToken, String accountName, KapuaId scopeId, KapuaId userId, String connectorName, String brokerIpOrHostName) {
        this.accountName = accountName;
        this.scopeId = scopeId;
        this.userId = userId;
        this.brokerIpOrHostName = brokerIpOrHostName;
        connectorDescriptor = ConnectorDescriptorProviders.getDescriptor(connectorName);
        if (connectorDescriptor == null) {
            throw new IllegalStateException(String.format("Unable to find connector descriptor for connector '%s'", connectorName));
        }
        updateFullClientId();
        principal = new KapuaPrincipalImpl(accessToken,
                userName,
                clientId,
                clientIp);
    }

    public void updatePermissions(boolean[] hasPermissions) {
        this.hasPermissions = hasPermissions;
    }

    public void updateKapuaConnectionId(DeviceConnection deviceConnection) {
        kapuaConnectionId = deviceConnection != null ? deviceConnection.getId() : null;
    }

    public void updateOldConnectionId(String oldConnectionId) {
        this.oldConnectionId = oldConnectionId;
    }

    private void updateFullClientId() {
        fullClientId = MessageFormat.format(AclConstants.MULTI_ACCOUNT_CLIENT_ID, scopeId.getId().longValue(), clientId);
    }

    private void updateFullClientId(Long scopeId) {
        fullClientId = MessageFormat.format(AclConstants.MULTI_ACCOUNT_CLIENT_ID, scopeId, clientId);
    }

    public String getFullClientId() {
        return fullClientId;
    }

    public String getAccountName() {
        return accountName;
    }

    public String getBrokerId() {
        return brokerId;
    }

    public String getUserName() {
        return userName;
    }

    public KapuaId getScopeId() {
        return scopeId;
    }

    public long getScopeIdAsLong() {
        return scopeId != null ? scopeId.getId().longValue() : 0;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public KapuaPrincipal getPrincipal() {
        return principal;
    }

    public String getConnectionId() {
        return connectionId;
    }

    public String getOldConnectionId() {
        return oldConnectionId;
    }

    public ConnectorDescriptor getConnectorDescriptor() {
        return connectorDescriptor;
    }

    public KapuaId getKapuaConnectionId() {
        return kapuaConnectionId;
    }

    public KapuaId getUserId() {
        return userId;
    }

    public boolean[] getHasPermissions() {
        return hasPermissions;
    }

    public String getBrokerIpOrHostName() {
        return brokerIpOrHostName;
    }

    public void addAuthDestinationToLog(String message) {
        if (logger.isDebugEnabled()) {
            authDestinations.add(message);
        }
    }

    public void logAuthDestinationToLog() {
        if (!authDestinations.isEmpty()) {
            logger.debug("Authorization map:");
            for (String str : authDestinations) {
                logger.debug(str);
            }
        }
    }

}
