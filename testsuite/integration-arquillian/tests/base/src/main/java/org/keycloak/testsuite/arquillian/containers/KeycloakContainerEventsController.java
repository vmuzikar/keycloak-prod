/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.arquillian.containers;

import org.jboss.arquillian.container.spi.event.ContainerMultiControlEvent;
import org.jboss.arquillian.container.spi.event.StopClassContainers;
import org.jboss.arquillian.container.spi.event.StopManualContainers;
import org.jboss.arquillian.container.spi.event.StopSuiteContainers;
import org.jboss.arquillian.container.spi.event.UnDeployManagedDeployments;
import org.jboss.arquillian.container.test.impl.client.ContainerEventController;
import org.jboss.arquillian.core.api.Event;
import org.jboss.arquillian.core.api.annotation.Inject;
import org.jboss.arquillian.core.api.annotation.Observes;
import org.jboss.arquillian.test.spi.event.suite.AfterClass;
import org.jboss.arquillian.test.spi.event.suite.AfterSuite;

/**
 * Changes behaviour of original ContainerEventController to stop manual containers 
 * @AfterSuite, not @AfterClass
 * 
 * @see https://issues.jboss.org/browse/ARQ-2186
 * 
 * @author vramik
 */
public class KeycloakContainerEventsController extends ContainerEventController {

    @Inject
    private Event<ContainerMultiControlEvent> container;

    @Override
    public void execute(@Observes AfterSuite event) {
        container.fire(new StopManualContainers());
        container.fire(new StopSuiteContainers());
    }

    @Override
    public void execute(@Observes(precedence = 3) AfterClass event) {
        try {
            container.fire(new UnDeployManagedDeployments());
        } finally {
            container.fire(new StopClassContainers());
        }
    }
}
