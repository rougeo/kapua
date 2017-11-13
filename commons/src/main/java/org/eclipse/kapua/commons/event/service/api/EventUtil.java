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
package org.eclipse.kapua.commons.event.service.api;

import org.eclipse.kapua.commons.event.service.internal.KapuaEventImpl;
import org.eclipse.kapua.commons.model.id.KapuaEid;

/**
 * Utility to convert event from/to entity event
 * 
 * @since 1.0
 *
 */
public class EventUtil {

    private EventUtil() {

    }

    /**
     * Convert the service event entity to the service bus object
     * 
     * @param event
     * @return
     */
    public static org.eclipse.kapua.service.event.KapuaEvent toServiceEventBus(Event event) {
        org.eclipse.kapua.service.event.KapuaEvent newEvent = new org.eclipse.kapua.service.event.KapuaEvent();
        newEvent.setId(event.getId().toCompactId());
        newEvent.setContextId(event.getContextId());
        newEvent.setTimestamp(event.getTimestamp());
        newEvent.setUserId(event.getUserId());
        newEvent.setService(event.getService());
        newEvent.setEntityType(event.getEntityType());
        newEvent.setScopeId(event.getScopeId());
        newEvent.setEntityId(event.getEntityId());
        newEvent.setOperation(event.getOperation());
        newEvent.setInputs(event.getInputs());
        newEvent.setOutputs(event.getOutputs());
        newEvent.setStatus(event.getStatus());
        newEvent.setNote(event.getNote());
        return newEvent;
    }

    /**
     * Convert the service bus object to the service event entity
     * 
     * @param event
     * @return
     */
    public static Event fromServiceEventBus(org.eclipse.kapua.service.event.KapuaEvent event) {
        Event newEvent = new KapuaEventImpl();
        newEvent.setId(KapuaEid.parseCompactId(event.getId()));
        newEvent.setContextId(event.getContextId());
        newEvent.setTimestamp(event.getTimestamp());
        newEvent.setUserId(event.getUserId());
        newEvent.setService(event.getService());
        newEvent.setEntityType(event.getEntityType());
        newEvent.setScopeId(event.getScopeId());
        newEvent.setEntityId(event.getEntityId());
        newEvent.setOperation(event.getOperation());
        newEvent.setInputs(event.getInputs());
        newEvent.setOutputs(event.getOutputs());
        newEvent.setStatus(event.getStatus());
        newEvent.setNote(event.getNote());
        return newEvent;
    }

}
