/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.axis2.integration;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceGroupContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.AxisServiceGroup;
import org.apache.axis2.engine.ListenerManager;
import org.apache.axis2.transport.tcp.TCPServer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.namespace.QName;
import java.io.File;

public class UtilsTCPServer {
    private static int count = 0;

    private static TCPServer receiver;

    public static final int TESTING_PORT = 5555;

    public static final String FAILURE_MESSAGE = "Intentional Failure";

	private static final Log log = LogFactory.getLog(UtilsTCPServer.class);

    public static synchronized void deployService(AxisService service)
            throws AxisFault {

        receiver.getConfigurationContext().getAxisConfiguration().addService(service);
        ServiceGroupContext serviceGroupContext = new ServiceGroupContext(
                receiver.getConfigurationContext(), (AxisServiceGroup) service.getParent());
    }

    public static synchronized void unDeployService(QName service)
            throws AxisFault {
        receiver.getConfigurationContext().getAxisConfiguration().removeService(
                service.getLocalPart());
    }

    public static synchronized void start() throws Exception {
        if (count == 0) {

            // start tcp server

            File file = new File(org.apache.axis2.Constants.TESTING_REPOSITORY);
            System.out.println(file.getAbsoluteFile());
            if (!file.exists()) {
                throw new Exception("Repository directory does not exist");
            }

            ConfigurationContext er = ConfigurationContextFactory.createConfigurationContextFromFileSystem(file
                    .getAbsolutePath(), file
                    .getAbsolutePath() + "/conf/axis2.xml");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e1) {
                throw new AxisFault("Thread interuptted", e1);
            }
            receiver = new TCPServer(UtilServer.TESTING_PORT, er);
            receiver.start();

        }
        count++;
    }

    public static synchronized void stop() throws AxisFault {
        try {
            if (count == 1) {
                receiver.stop();
                count = 0;
                System.out.print("Server stopped .....");
            } else {
                count--;
            }
        } catch (AxisFault e) {
            log.error(e.getMessage(), e);
        }
        receiver.getConfigurationContext().terminate();
    }

}
