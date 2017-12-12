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
package org.eclipse.kapua.broker.core.plugin.authentication;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.ShiroException;
import org.eclipse.kapua.KapuaException;
import org.eclipse.kapua.KapuaIllegalAccessException;
import org.eclipse.kapua.broker.core.plugin.Acl;
import org.eclipse.kapua.broker.core.plugin.AclConstants;
import org.eclipse.kapua.broker.core.plugin.KapuaConnectionContext;
import org.eclipse.kapua.broker.core.plugin.KapuaDuplicateClientIdException;
import org.eclipse.kapua.commons.security.KapuaSecurityUtils;
import org.eclipse.kapua.service.authorization.permission.Actions;
import org.eclipse.kapua.service.device.registry.ConnectionUserCouplingMode;
import org.eclipse.kapua.service.device.registry.connection.DeviceConnection;
import org.eclipse.kapua.service.device.registry.connection.DeviceConnectionCreator;
import org.eclipse.kapua.service.device.registry.connection.DeviceConnectionStatus;

import com.codahale.metrics.Timer.Context;

public class UserAuthentictionLogic extends AuthenticationLogic {

    @Override
    public List<org.eclipse.kapua.broker.core.plugin.authentication.AuthorizationEntry> connect(KapuaConnectionContext kcc, AuthenticationCallback authenticationCallback) throws KapuaException {
        Context loginNormalUserTimeContext = loginMetric.getNormalUserTime().time();
        Context loginCheckAccessTimeContext = loginMetric.getCheckAccessTime().time();
        boolean[] hasPermissions = new boolean[] {
                // TODO check the permissions... move them to a constants class?
                authorizationService.isPermitted(permissionFactory.newPermission(BROKER_DOMAIN, Actions.connect, kcc.getScopeId())),
                authorizationService.isPermitted(permissionFactory.newPermission(DEVICE_MANAGEMENT_DOMAIN, Actions.write, kcc.getScopeId())),
                authorizationService.isPermitted(permissionFactory.newPermission(DATASTORE_DOMAIN, Actions.read, kcc.getScopeId())),
                authorizationService.isPermitted(permissionFactory.newPermission(DATASTORE_DOMAIN, Actions.write, kcc.getScopeId()))
        };
        if (!hasPermissions[AclConstants.BROKER_CONNECT_IDX]) {
            throw new KapuaIllegalAccessException(permissionFactory.newPermission(BROKER_DOMAIN, Actions.connect, kcc.getScopeId()).toString());
        }
        loginCheckAccessTimeContext.stop();

        kcc.updatePermissions(hasPermissions);
        List<org.eclipse.kapua.broker.core.plugin.authentication.AuthorizationEntry> authorizationEntries = buildAuthorizationMap(kcc);

        Context loginFindClientIdTimeContext = loginMetric.getFindClientIdTime().time();
        DeviceConnection deviceConnection = KapuaSecurityUtils.doPrivileged(() -> deviceConnectionService.findByClientId(kcc.getScopeId(), kcc.getClientId()));
        loginFindClientIdTimeContext.stop();
        // enforce the user-device bound
        enforceDeviceConnectionUserBound(KapuaSecurityUtils.doPrivileged(() -> deviceConnectionService.getConfigValues(kcc.getScopeId())), deviceConnection, kcc.getScopeId(), kcc.getUserId());

        Context loginFindDevTimeContext = loginMetric.getFindDevTime().time();

        String previousConnectionId = authenticationCallback.getConnectionId(kcc);
        boolean stealingLinkDetected = (previousConnectionId != null);
        if (deviceConnection == null) {
            DeviceConnectionCreator deviceConnectionCreator = deviceConnectionFactory.newCreator(kcc.getScopeId());
            deviceConnectionCreator.setClientId(kcc.getClientId());
            deviceConnectionCreator.setClientIp(kcc.getClientIp());
            deviceConnectionCreator.setProtocol(kcc.getConnectorDescriptor().getTransportProtocol());
            deviceConnectionCreator.setServerIp(kcc.getBrokerIpOrHostName());
            deviceConnectionCreator.setUserId(kcc.getUserId());
            deviceConnectionCreator.setUserCouplingMode(ConnectionUserCouplingMode.INHERITED);
            deviceConnectionCreator.setAllowUserChange(false);
            deviceConnection = KapuaSecurityUtils.doPrivileged(() -> deviceConnectionService.create(deviceConnectionCreator));
        } else {
            deviceConnection.setClientIp(kcc.getClientIp());
            deviceConnection.setProtocol(kcc.getConnectorDescriptor().getTransportProtocol());
            deviceConnection.setServerIp(kcc.getBrokerIpOrHostName());
            deviceConnection.setUserId(kcc.getUserId());
            deviceConnection.setStatus(DeviceConnectionStatus.CONNECTED);
            deviceConnection.setAllowUserChange(false);
            final DeviceConnection deviceConnectionToUpdate = deviceConnection;
            KapuaSecurityUtils.doPrivileged(() -> deviceConnectionService.update(deviceConnectionToUpdate));
            // TODO implement the banned status
            // if (DeviceStatus.DISABLED.equals(device.getStatus())) {
            // throw new KapuaIllegalAccessException("clientId - This client ID is disabled and cannot connect");
            // }
            // TODO manage the stealing link event (may be a good idea to use different connect status (connect -stealing)?
            if (stealingLinkDetected) {
                loginMetric.getStealingLinkConnect().inc();

                // stealing link detected, skip info
                logger.warn("Detected Stealing link for cliend id {} - account - last connection id was {} - current connection id is {} - IP: {} - No connection status changes!",
                        new Object[] { kcc.getClientId(), kcc.getAccountName(), previousConnectionId, kcc.getConnectionId(), kcc.getClientIp() });
            }
        }
        loginFindDevTimeContext.stop();
        loginNormalUserTimeContext.stop();
        return authorizationEntries;
    }

    @Override
    public void disconnect(KapuaConnectionContext kcc, AuthenticationCallback authenticationCallback, Throwable error) {
        boolean stealingLinkDetected = false;
        if (kcc.getOldConnectionId() != null) {
            stealingLinkDetected = !kcc.getOldConnectionId().equals(kcc.getConnectionId());
        } else {
            logger.error("Cannot find connection id for client id {} on connection map. Correct connection id is {} - IP: {}",
                    new Object[] { kcc.getClientId(), kcc.getConnectionId(), kcc.getClientIp() });
        }
        if (stealingLinkDetected) {
            loginMetric.getStealingLinkDisconnect().inc();
            // stealing link detected, skip info
            logger.warn("Detected Stealing link for cliend id {} - account id {} - last connection id was {} - current connection id is {} - IP: {} - No disconnection info will be added!",
                    new Object[] { kcc.getClientId(), kcc.getScopeId(), kcc.getOldConnectionId(), kcc.getConnectionId(), kcc.getClientIp() });
        } else {
            final DeviceConnection deviceConnection;
            try {
                deviceConnection = KapuaSecurityUtils.doPrivileged(() -> deviceConnectionService.findByClientId(kcc.getScopeId(), kcc.getClientId()));
            } catch (Exception e) {
                throw new ShiroException("Error while looking for device connection on updating the device!", e);
            }
            if (deviceConnection != null) {
                // the device connection must be not null
                // update device connection (if the disconnection wasn't caused by a stealing link)
                if (error instanceof KapuaDuplicateClientIdException) {
                    logger.debug("Skip device connection status update since is coming from a stealing link condition. Client id: {} - Connection id: {}",
                            new Object[] { kcc.getClientId(), kcc.getConnectionId() });
                } else {
                    deviceConnection.setStatus(error == null ? DeviceConnectionStatus.DISCONNECTED : DeviceConnectionStatus.MISSING);
                    try {
                        KapuaSecurityUtils.doPrivileged(() -> {
                            deviceConnectionService.update(deviceConnection);
                            return null;
                        });
                    } catch (Exception e) {
                        throw new ShiroException("Error while updating the device connection status!", e);
                    }
                }
            }
        }
    }

    protected List<AuthorizationEntry> buildAuthorizationMap(KapuaConnectionContext kcc) {
        ArrayList<AuthorizationEntry> ael = new ArrayList<AuthorizationEntry>();
        ael.add(createAuthorizationEntry(kcc, Acl.WRITE_ADMIN, AclConstants.ACL_AMQ_ADVISORY));

        // addConnection checks BROKER_CONNECT_IDX permission before call this method
        // then here user has BROKER_CONNECT_IDX permission and if check isn't needed
        // if (hasPermissions[BROKER_CONNECT_IDX]) {
        if (kcc.getHasPermissions()[AclConstants.DEVICE_MANAGE_IDX]) {
            ael.add(createAuthorizationEntry(kcc, Acl.ALL, formatAcl(AclConstants.ACL_CTRL_ACC, kcc)));
        } else {
            ael.add(createAuthorizationEntry(kcc, Acl.ALL, formatAclFull(AclConstants.ACL_CTRL_ACC_CLI, kcc)));
        }
        if (kcc.getHasPermissions()[AclConstants.DATA_MANAGE_IDX]) {
            ael.add(createAuthorizationEntry(kcc, Acl.ALL, formatAcl(AclConstants.ACL_DATA_ACC, kcc)));
        } else if (kcc.getHasPermissions()[AclConstants.DATA_VIEW_IDX]) {
            ael.add(createAuthorizationEntry(kcc, Acl.READ_ADMIN, formatAcl(AclConstants.ACL_DATA_ACC, kcc)));
            ael.add(createAuthorizationEntry(kcc, Acl.WRITE, formatAclFull(AclConstants.ACL_DATA_ACC_CLI, kcc)));
        } else {
            ael.add(createAuthorizationEntry(kcc, Acl.ALL, formatAclFull(AclConstants.ACL_DATA_ACC_CLI, kcc)));
        }
        ael.add(createAuthorizationEntry(kcc, Acl.WRITE_ADMIN, formatAcl(AclConstants.ACL_CTRL_ACC_REPLY, kcc)));

        // Write notify to any client Id and any application and operation
        ael.add(createAuthorizationEntry(kcc, Acl.WRITE, formatAclFull(AclConstants.ACL_CTRL_ACC_NOTIFY, kcc)));

        kcc.logAuthDestinationToLog();

        return ael;
    }
}
