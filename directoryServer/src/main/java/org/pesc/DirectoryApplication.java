/*
 * Copyright (c) 2017. California Community Colleges Technology Center
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.pesc;

import org.apache.catalina.startup.Tomcat;
import org.apache.cxf.transport.servlet.CXFServlet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@ComponentScan
@EnableAsync
public class DirectoryApplication {


	public static void main(final String[] args) {
		SpringApplication.run(DirectoryApplication.class, args);
	}


    @Bean
    public ServletRegistrationBean servletRegistrationBean(final ApplicationContext context) {
        return new ServletRegistrationBean(new CXFServlet(), "/services/*");
    }


    /**
     * Enables JNDI On Tomcat
     * @return TomcatEmbeddedServletContainerFactory
     */
    @Bean
    public TomcatEmbeddedServletContainerFactory tomcatFactory(@Value("${http.port}") final Integer port) {
        TomcatEmbeddedServletContainerFactory factory = new TomcatEmbeddedServletContainerFactory(port) {

            @Override
            protected TomcatEmbeddedServletContainer getTomcatEmbeddedServletContainer(
                    final Tomcat tomcat) {
                tomcat.enableNaming();
                return super.getTomcatEmbeddedServletContainer(tomcat);
            }

            //Uncomment the code below if the server is used without a load balancer that's handling HTTPS.
            /*

            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
            */

        };

        //HTTPS
        // factory.addAdditionalTomcatConnectors(createStandardConnector(port));


        /* Not using AJP do to reverse proxy issues revolving around redirects that use an absolute path.  The
        funny thing is that the exact same configuration for HTTP works fine, so something up with AJP. */

        /*

        Connector ajpConnector = new Connector("AJP/1.3");
        ajpConnector.setPort(8009);
        ajpConnector.setSecure(false);
        ajpConnector.setAllowTrace(false);
        ajpConnector.setScheme("http");
        factory.addAdditionalTomcatConnectors(ajpConnector);
        */


        return factory;
    }


    // private Connector createStandardConnector(final Integer port) {
    // Connector connector = new
    // Connector("org.apache.coyote.http11.Http11NioProtocol");
    // connector.setScheme("http");
    // connector.setSecure(false);
    // //connector.setRedirectPort(securePort);
    // connector.setPort(port);
    // return connector;
    // }



}
