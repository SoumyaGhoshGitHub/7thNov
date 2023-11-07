package com.kovair.devops;

import com.kovair.devops.util.ActiveDirectory;
import com.kovair.devops.model.LdapProfile;
import com.kovair.devops.util.KovairEncryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.  BadCredentialsException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import com.kovair.devops.dbManager.LdapRepository;
import com.kovair.devops.dbManager.UserRepository;
import com.kovair.devops.model.User;
import com.kovair.devops.plugin.manager.KovairLogManager;
import com.kovair.devops.util.KovairUtility;
import javax.servlet.http.HttpServletRequest;

@Component
public class CustomLdapAuthenticationProvider implements AuthenticationProvider {

    @Autowired(required = false)
    private HttpServletRequest request;
    
    @Autowired
    UserDetailsService userDetailsService;
    
    @Autowired
    LdapRepository ldapRepository;
    
    @Autowired
    ActiveDirectory activeDirectory;
    
    @Autowired
    UserRepository userRepository;
    
    @Autowired 
    GlobalValues globalValues;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException 
    {
        /*************** Comment **********************************
         * Product Name   : Kovair DevOps         
         * Author         : Abdul Gaffar
         * PM             : Debasish Pradhan
         * Reviewer       : 
         * Method Name    : authenticate
         * Purpose        : Method to authenticate ldap user..
         * Changed On     :
         * Changed by     :
         * Changes Details:
        ************************************************************/
        
        UserDetails user = null;
        User userFromDB = null;
        LdapProfile profile = null;
        boolean isAuthenticated = false;
        String username = "";
        String usernameForFutureUse = "";
        String password = "";
        String decryptedPass = "";
        String profileId = "";
        try {

            KovairLogManager.KovairLog.info("CustomLdapAuthenticationProvider : Method : authenticate : Starts.");
            if (authentication != null) {

                username = authentication.getName();
                usernameForFutureUse = authentication.getName();
                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : username : " + username);
                
                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling getActualUserName()");
                username = activeDirectory.getActualUserName(username);
                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling getActualUserName()");
                    
                profileId = request.getParameter("domainSelect");
                if(profileId == null)
                {
                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling findByUsername()");
                    userFromDB = userRepository.findByUsernameAndStatusNot(username,'X');
                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling findByUsername()");
                    
                    if(userFromDB != null)
                    {
                        profileId = userFromDB.getLdapprofileid().toString();
                    }
                    else
                    {
                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : userFromDB object is null.");
                    }
                }
                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : profileId received from login page : " + profileId);
                if (profileId != null && !profileId.isEmpty() && !profileId.equalsIgnoreCase("0")) {
                    
                    
                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : actualusername : " + username);

                    password = authentication.getCredentials().toString();
                    if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling findByUsernameAndStatusNot()");
                        userFromDB = userRepository.findByUsernameAndStatusNot(username,'X');
                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling findByUsernameAndStatusNot()");
                        if(userFromDB != null)
                        {
                            if (userFromDB.getStatus() == 'Y') {
                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling loadUserByUsername()");
                                user = userDetailsService.loadUserByUsername(username);
                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling loadUserByUsername()");
                                if (user != null) {
                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling findById()");
                                    profile = ldapRepository.findById(Long.parseLong(profileId));
                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling findById()");
                                    if (profile != null) {
                                        if (profile.getIsactive() == 'Y') {

                                            decryptedPass = KovairEncryption.decrypt(profile.getBinduserpass());

                                            if (decryptedPass != null && !decryptedPass.isEmpty()) {
                                                profile.setBinduserpass(decryptedPass);
                                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling authenticateLdapUser()");
                                                isAuthenticated = activeDirectory.authenticateLdapUser(profile, "NotImplemented", username, password, false);
                                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling authenticateLdapUser()");
                                                if (isAuthenticated) {
                                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : User authenticated successfully.");
                                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Calling createSuccessfulAuthentication() constructor.");
                                                    return createSuccessfulAuthentication(authentication, user);
                                                }
                                                else {
                                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Authentication Failed.");
                                                }
                                            }
                                            else {
                                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : binduserpass decryption unsuccessfull.");
                                                throw new AuthenticationServiceException("Login Failed! Domain not found.");
                                            }
                                        }
                                        else {
                                            KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Ldap profile found but is inactive.");
                                            throw new AuthenticationServiceException("LDAP profile is disabled, please contact administrator.");
                                        }
                                    } else {
                                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : profile object is null.");
                                        throw new AuthenticationServiceException("Login Failed! Domain not found.");
                                    }
                                } else {
                                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : user object is null.");
                                    throw new AuthenticationServiceException("Login Failed! User not found.");
                                }
                            } else if (userFromDB.getStatus() == 'N') {
                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : User found but is inactive.");
                                throw new AuthenticationServiceException("User account is disabled, please contact administrator.");
                            } else {
                                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : User not found.");
                                throw new AuthenticationServiceException("Login Failed! User not found.");
                            }
                        }
                        else
                        {
                            KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : username or password is null or empty.");
                            throw new AuthenticationServiceException("Login Failed! User not found.");
                        }
                    } else {
                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : username or password is null or empty.");
                        throw new AuthenticationServiceException("Login Failed! Invalid username or password.");
                    }
                } else {
                    if(username.equalsIgnoreCase(""))
                    {
                        username = usernameForFutureUse; 
                    }
                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Before calling findByUsernameAndStatusNot()");
                    userFromDB = userRepository.findByUsernameAndStatusNot(username, 'X');
                    KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : After calling findByUsernameAndStatusNot()");
                    if (userFromDB != null) {
                        if (userFromDB.getIsldapuser() == 'Y') {
                            KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : profileId is invalid, authentication request not for ldap user.");
                            throw new AuthenticationServiceException("Login Failed! Domain not found.");
                        } else {
                            KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : It is not a ldap user.");
                            //throw new AuthenticationServiceException("NonLdapUser");
                        }
                    } else {
                        KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : username or password is null or empty.");
                        throw new AuthenticationServiceException("Login Failed! User not found.");
                    }
                }
            } else {
                KovairLogManager.KovairLog.debug("CustomLdapAuthenticationProvider : Method : authenticate : Authentication object received as argument is null.");
                throw new AuthenticationServiceException("Login Failed! authentication is null.");
            }
        } catch (Exception e) {
            KovairLogManager.KovairLog.error("LdapManager : Method : authenticate : Error : " + e.getMessage()
                    + "  StackTrace : " + KovairUtility.GetStackTraceMessage(e));
            globalValues.LDAP_EXCEPTION_OBJ = e;
            throw new BadCredentialsException(e.getMessage());
            
        } finally {
            KovairLogManager.KovairLog.info("CustomLdapAuthenticationProvider : Method : authenticate : Ends.");
        }
        return null;
    }

    private Authentication createSuccessfulAuthentication(final Authentication authentication, final UserDetails user)
    {
    	
    	/*************** Comment **********************************
         * Product Name   : Kovair DevOps         
         * Author         : Abdul Gaffar
         * PM             : Debasish Pradhan
         * Reviewer       : 
         * Method Name    : createSuccessfulAuthentication
         * Purpose        : Authentication method using username and password
         * Changed On     :
         * Changed by     :
         * Changes Details:
        ************************************************************/
    	
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, authentication.getCredentials(), user.getAuthorities());
        token.setDetails(authentication.getDetails());
        return token;
    }
    
    
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    } 
}
