/*******************************************************************************
 * Copyright (c) 2011, 2017 Eurotech and/or its affiliates and others
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Eurotech - initial API and implementation
 *******************************************************************************/
package org.eclipse.kapua.commons.event.service.internal;

import org.eclipse.kapua.commons.event.service.api.Event;
import org.eclipse.kapua.commons.event.service.api.KapuaEventCreator;
import org.eclipse.kapua.commons.event.service.api.KapuaEventListResult;
import org.eclipse.kapua.commons.event.service.api.KapuaEventStoreFactory;
import org.eclipse.kapua.commons.event.service.api.KapuaEventStoreQuery;
import org.eclipse.kapua.locator.KapuaProvider;
import org.eclipse.kapua.model.id.KapuaId;

@KapuaProvider
public class KapuaEventStoreFactoryImpl implements KapuaEventStoreFactory {

    @Override
    public Event newEntity(KapuaId scopeId) {
        return new KapuaEventImpl(scopeId);
    }

    @Override
    public KapuaEventCreator newCreator(KapuaId scopeId) {
        return new KapuaEventCreatorImpl(scopeId);
    }

    @Override
    public KapuaEventStoreQuery newQuery(KapuaId scopeId) {
        return new KapuaEventStoreQueryImpl(scopeId);
    }

    @Override
    public KapuaEventListResult newListResult() {
        return new KapuaEventListResultImpl();
    }
}