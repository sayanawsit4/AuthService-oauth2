package com.mykbox.controller;

import com.mykbox.config.AuthorityPropertyEditor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequestMapping("clients")
public class ClientsController {

    @Autowired
    private JdbcClientDetailsService clientsDetailsService;

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.registerCustomEditor(GrantedAuthority.class, new AuthorityPropertyEditor());
    }

    @RequestMapping(value = "/form", method = RequestMethod.GET)
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String showEditForm(@RequestParam(value = "client", required = false) String clientId, Model model) {

        ClientDetails clientDetails;
        clientDetails = Optional.ofNullable(clientId)
                .map(s -> clientsDetailsService.loadClientByClientId(s))
                .orElse(new BaseClientDetails());
        model.addAttribute("clientDetails", clientDetails);
        return "form";
    }


    @RequestMapping(value = "/edit", method = RequestMethod.POST)
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String editClient(
            @ModelAttribute BaseClientDetails clientDetails,
            @RequestParam(value = "newClient", required = false) Optional <String> newClient) {

     if(newClient.isPresent())
         clientsDetailsService.addClientDetails(clientDetails);
     else
         clientsDetailsService.updateClientDetails(clientDetails);

     Optional.ofNullable(clientDetails.getClientSecret())
            .ifPresent( s -> clientsDetailsService.updateClientSecret(clientDetails.getClientId(), clientDetails.getClientSecret()));
        return "redirect:/";
    }

    @RequestMapping(value = "/{client.clientId}/delete", method = RequestMethod.GET)
    public String deleteClient(@ModelAttribute BaseClientDetails ClientDetails, @PathVariable("client.clientId") String id) {
        clientsDetailsService.removeClientDetails(id);
        return "redirect:/";
    }
}