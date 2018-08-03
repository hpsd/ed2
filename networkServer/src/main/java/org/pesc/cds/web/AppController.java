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

package org.pesc.cds.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.pesc.cds.service.OrganizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Collection;

@Controller
public class AppController {

    private static final Log log = LogFactory.getLog(AppController.class);

    @Value("${directory.server.base.url}")
    private String directoryServer;

    private final String localServerId;

    private JSONObject organization;

    private final OrganizationService organizationService;

    // @Autowired
    // private TransactionService transactionService;

    @Autowired
    public AppController( @Value("${networkServer.id}") final String edExID, final OrganizationService organizationService) {
        this.organizationService = organizationService;
        localServerId = edExID;
        // organization =
        // organizationService.getOrganization(Integer.valueOf(localServerId));
    }


    private boolean hasRole(final Collection<? extends GrantedAuthority> authorities, final String role) {
        boolean hasRole = false;
        for (GrantedAuthority authority : authorities) {
            hasRole = authority.getAuthority().equals(role);
            if (hasRole) {
                break;
            }
        }
        return hasRole;
    }


    private boolean buildCommonModel(final Model model) {
        model.addAttribute("directoryServer", directoryServer);

        boolean isAuthenticated = false;


        //Check if the user is autenticated
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated() &&
                //when Anonymous Authentication is enabled
                !(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            isAuthenticated = true;

            model.addAttribute("hasSupportRole", hasRole(authorities, "ROLE_SUPPORT"));
            model.addAttribute("hasAdminRole", hasRole(authorities, "ROLE_ORG_ADMIN"));

            // model.addAttribute("roles", roleRepo.findAll() );
            org.pesc.cds.model.User activeUser = new org.pesc.cds.model.User();
            activeUser.setName(authentication.getName());
            model.addAttribute("activeUser", activeUser);

        } else {
            model.addAttribute("hasSupportRole", false);
            model.addAttribute("hasAdminRole", false);
        }

        model.addAttribute("isAuthenticated", isAuthenticated);


        return isAuthenticated;

    }

    /*
    @RequestMapping("/unauthenticated")
    public String unauthenticated() {
        return "redirect:/?error=true";
    }
    */


    @RequestMapping({"/documentation"})
    public String getDocumentation(final Model model) throws JSONException {
        buildCommonModel(model);

        model.addAttribute("organizationName", "Digitary");
        model.addAttribute("organizationId", "1232");

        return "documentation";
    }



    private void setContentType(final HttpServletResponse response, final String fileFormat) {
        if (fileFormat.equalsIgnoreCase("pdf")) {
            response.setContentType("application/pdf");
        } else if (fileFormat.equalsIgnoreCase("text")) {
            response.setContentType("text/plain");
        } else if (fileFormat.equalsIgnoreCase("xml")) {
            response.setContentType("text/xml");
        } else if (fileFormat.equalsIgnoreCase("pescxml")) {
            response.setContentType("text/xml");
        } else if (fileFormat.equalsIgnoreCase("image")) {
            response.setContentType("image/png"); //TODO: how to get actual MIME type ???
        } else if (fileFormat.equalsIgnoreCase("edi")) {
            response.setContentType("application/edi-x12"); //TODO: could be application/edifact ???
        }

    }




    @RequestMapping("/admin")
    public String getAdminPage(final Model model) {

        buildCommonModel(model);

        return "home";
    }

    @RequestMapping("/upload-status")
    public String getUploadStatus(final Model model) {

        buildCommonModel(model);

        return "fragments :: upload-status";
    }

    @RequestMapping("/transaction-report")
    public String getTransactionsPage(final Model model) {

        buildCommonModel(model);

        return "fragments :: transactions";
    }

    private JSONObject getOrganization() {
        if (organization == null) {
            organization = organizationService.getOrganization(Integer.valueOf(localServerId));
        }

        // if (organization == null) {
        // throw new IllegalStateException("Failed to retrieve organization info from
        // directory for network server ID " + localServerId );
        // }

        return organization;
    }

    @RequestMapping("/upload")
    public String getTransfersPage(final Model model) throws JSONException {

        buildCommonModel(model);

        // getOrganization();

        boolean institution = true; // organizationService.isInstitution(organization);
        model.addAttribute("institution", institution);
        return "fragments :: upload";
    }

    @RequestMapping("/transcript-request-form")
    public String getTranscriptRequestForm(final Model model) {

        buildCommonModel(model);

        return "fragments :: transcript-request-form";
    }

    @RequestMapping("/actuator-view")
    public String getActuatorView(final Model model) {

        buildCommonModel(model);

        return "fragments :: actuator-view";
    }

    @RequestMapping({"/", "/home"})
    public String viewHome(final Model model) {

        buildCommonModel(model);
        return "home";
    }

    @RequestMapping("/about")
    public String getAboutPage(final Model model) {
        buildCommonModel(model);

        return "fragments :: about";
    }

    @RequestMapping("/user-account")
    public String userAccount(final Model model, final Principal principal) {
        model.addAttribute("name", principal.getName());
        return "fragments :: user-account";
    }



}
