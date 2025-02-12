package stirling.software.SPDF.config.security.saml2;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.UUID;

import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import stirling.software.SPDF.model.ApplicationProperties;
import stirling.software.SPDF.model.ApplicationProperties.Security.SAML2;

@Configuration
@Slf4j
@ConditionalOnProperty(value = "security.saml2.enabled", havingValue = "true")
public class SAML2Configuration {

    public static final String SAML_2_AUTHN_REQUEST =
            "org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository.SAML2_AUTHN_REQUEST";
    public static final String NAMEID_FORMAT_UNSPECIFIED =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

    private final ApplicationProperties applicationProperties;

    public SAML2Configuration(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    @Bean
    @ConditionalOnProperty(name = "security.saml2.enabled", havingValue = "true")
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
        SAML2 samlConf = applicationProperties.getSecurity().getSaml2();
        X509Certificate idpCert = CertificateUtils.readCertificate(samlConf.getIdpCert());
        Saml2X509Credential verificationCredential = Saml2X509Credential.verification(idpCert);
        Resource privateKeyResource = samlConf.getPrivateKey();
        Resource certificateResource = samlConf.getSpCert();
        Saml2X509Credential signingCredential =
                new Saml2X509Credential(
                        CertificateUtils.readPrivateKey(privateKeyResource),
                        CertificateUtils.readCertificate(certificateResource),
                        Saml2X509CredentialType.SIGNING);
        RelyingPartyRegistration rp =
                RelyingPartyRegistration.withRegistrationId(samlConf.getRegistrationId())
                        .signingX509Credentials(c -> c.add(signingCredential))
                        .entityId(samlConf.getIdpIssuer())
                        //                        .nameIdFormat(NAMEID_FORMAT_UNSPECIFIED)
                        .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                        .singleLogoutServiceLocation(samlConf.getIdpSingleLogoutUrl())
                        .singleLogoutServiceResponseLocation("http://localhost:8080/login")
                        .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                        .assertionConsumerServiceLocation(
                                "{baseUrl}/login/saml2/sso/{registrationId}")
                        .assertingPartyMetadata(
                                metadata ->
                                        metadata.entityId(samlConf.getIdpIssuer())
                                                .verificationX509Credentials(
                                                        c -> c.add(verificationCredential))
                                                .singleSignOnServiceBinding(
                                                        Saml2MessageBinding.POST)
                                                .singleSignOnServiceLocation(
                                                        samlConf.getIdpSingleLoginUrl())
                                                .singleLogoutServiceBinding(
                                                        Saml2MessageBinding.POST)
                                                .singleLogoutServiceLocation(
                                                        samlConf.getIdpSingleLogoutUrl())
                                                .wantAuthnRequestsSigned(true))
                        .build();
        return new InMemoryRelyingPartyRegistrationRepository(rp);
    }

    @Bean
    @ConditionalOnProperty(name = "security.saml2.enabled", havingValue = "true")
    public OpenSaml4AuthenticationRequestResolver authenticationRequestResolver(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        SAML2 saml2Conf = applicationProperties.getSecurity().getSaml2();
        OpenSaml4AuthenticationRequestResolver resolver =
                new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationRepository);

        resolver.setAuthnRequestCustomizer(
                customizer -> {
                    HttpServletRequest request = customizer.getRequest();
                    AuthnRequest authnRequest = customizer.getAuthnRequest();
                    HttpSessionSaml2AuthenticationRequestRepository requestRepository =
                            new HttpSessionSaml2AuthenticationRequestRepository();
                    AbstractSaml2AuthenticationRequest saml2AuthenticationRequest =
                            requestRepository.loadAuthenticationRequest(request);
                    Audience audience =
                            new AudienceBuilder().buildObject(Audience.DEFAULT_ELEMENT_NAME);
                    AudienceRestriction audienceRestriction =
                            new AudienceRestrictionBuilder()
                                    .buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
                    Conditions conditions =
                            new ConditionsBuilder().buildObject(Conditions.DEFAULT_ELEMENT_NAME);

                    Instant notBefore = Instant.now();
                    conditions.setNotBefore(notBefore);
                    conditions.setNotOnOrAfter(notBefore.plus(10, ChronoUnit.MINUTES));

                    audience.setURI(saml2Conf.getRegistrationId());
                    audienceRestriction.getAudiences().add(audience);
                    conditions.getAudienceRestrictions().add(audienceRestriction);
                    authnRequest.setConditions(conditions);
                    authnRequest.setProviderName(saml2Conf.getProvider());

                    if (authnRequest.getID() == null && saml2AuthenticationRequest != null) {
                        log.debug(
                                "No ID set for SAML 2 authentication request. Will attempt to retrieve from the current HTTP session");
                        String authenticationRequestId = saml2AuthenticationRequest.getId();

                        if (!authenticationRequestId.isBlank()) {
                            authnRequest.setID(authenticationRequestId);
                        } else {
                            log.warn(
                                    "No ID found for SAML 2 authentication request. Generating new ID");
                            authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
                        }
                    } else {
                        log.warn(
                                "No ID found for SAML 2 authentication request. Generating new ID");
                        authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
                    }

                    Saml2PostAuthenticationRequest samlPostRequest =
                            Saml2PostAuthenticationRequest.withRelyingPartyRegistration(
                                            relyingPartyRegistrationRepository.findByRegistrationId(
                                                    saml2Conf.getRegistrationId()))
                                    .id(authnRequest.getID())
                                    .samlRequest("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                                    .relayState("")
                                    .build();
                    requestRepository.saveAuthenticationRequest(samlPostRequest, request, null);

                    logAuthnRequestDetails(authnRequest);
                    logHttpRequestDetails(request);
                });
        return resolver;
    }

    private static void logAuthnRequestDetails(AuthnRequest authnRequest) {
        String message =
                """
                        AuthnRequest:

                        ID: {}
                        Issuer: {}
                        IssueInstant: {}
                        AssertionConsumerService (ACS) URL: {}
                        """;
        log.debug(
                message,
                authnRequest.getID(),
                authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : null,
                authnRequest.getIssueInstant(),
                authnRequest.getAssertionConsumerServiceURL());

        if (authnRequest.getNameIDPolicy() != null) {
            log.debug("NameIDPolicy Format: {}", authnRequest.getNameIDPolicy().getFormat());
        }
    }

    private static void logHttpRequestDetails(HttpServletRequest request) {
        log.debug("HTTP Headers: ");
        Collections.list(request.getHeaderNames())
                .forEach(
                        headerName ->
                                log.debug("{}: {}", headerName, request.getHeader(headerName)));
        String message =
                """
                        HTTP Request Method: {}
                        Session ID: {}
                        Request Path: {}
                        Query String: {}
                        Remote Address: {}

                        SAML Request Parameters:

                        SAMLRequest: {}
                        RelayState: {}
                        """;
        log.debug(
                message,
                request.getMethod(),
                request.getSession().getId(),
                request.getRequestURI(),
                request.getQueryString(),
                request.getRemoteAddr(),
                request.getParameter("SAMLRequest"),
                request.getParameter("RelayState"));
    }

    // todo: look up how to extract AbstractSaml2AuthenticationRequest from request in spring
    // examples
    // todo: try below to sign:
    // todo:
    // this.saml.withSigningKeys(registration.getSigningX509Credentials()).algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms()).sign(authnRequest);
    //    public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest
    // request, RelyingPartyRegistration serviceProviderRegistration) {
    //		RelyingPartyRegistrationPlaceholderResolvers.UriResolver uriResolver =
    //				RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request,
    // serviceProviderRegistration);
    //		String entityId = uriResolver.resolve(serviceProviderRegistration.getEntityId());
    //		String assertionConsumerServiceLocation = uriResolver
    //			.resolve(serviceProviderRegistration.getAssertionConsumerServiceLocation());
    //
    //		AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
    //		authnRequest.setForceAuthn(false);
    //		authnRequest.setIsPassive(false);
    //
    //	authnRequest.setProtocolBinding(serviceProviderRegistration.getAssertionConsumerServiceBinding().getUrn());
    //
    //		Issuer iss = new IssuerBuilder().buildObject();
    //		iss.setValue(entityId);
    //		authnRequest.setIssuer(iss);
    //
    //	authnRequest.setDestination(serviceProviderRegistration.getAssertingPartyMetadata().getSingleSignOnServiceLocation());
    //		authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceLocation);
    //
    //		if (serviceProviderRegistration.getNameIdFormat() != null) {
    //			NameIDPolicy nameIdPolicy = new NameIDPolicyBuilder().buildObject();
    //			nameIdPolicy.setFormat(serviceProviderRegistration.getNameIdFormat());
    //			authnRequest.setNameIDPolicy(nameIdPolicy);
    //		}
    //		authnRequest.setIssueInstant(Instant.now(Clock.systemUTC()));
    ////		this.parametersConsumer.accept(new AuthnRequestParameters(request,
    // serviceProviderRegistration, authnRequest));
    //
    //		if (authnRequest.getID() == null) {
    //			String var10001 = UUID.randomUUID().toString();
    //			authnRequest.setID("ARQ" + var10001.substring(1));
    //		}
    //
    //		String relayState = this.relayStateResolver.convert(request);
    //		Saml2MessageBinding binding =
    // serviceProviderRegistration.getAssertingPartyMetadata().getSingleSignOnServiceBinding();
    //
    //		if (binding == Saml2MessageBinding.POST) {
    //			if (serviceProviderRegistration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
    //					|| serviceProviderRegistration.isAuthnRequestsSigned()) {
    //				this.saml.withSigningKeys(serviceProviderRegistration.getSigningX509Credentials())
    //
    //	.algorithms(serviceProviderRegistration.getAssertingPartyMetadata().getSigningAlgorithms())
    //					.sign(authnRequest);
    //			}
    //
    //			String xml = serialize(authnRequest);
    //			String encoded = Saml2Utils.withDecoded(xml).encode();
    //			return (T)
    // Saml2PostAuthenticationRequest.withRelyingPartyRegistration(serviceProviderRegistration)
    //				.samlRequest(encoded)
    //				.relayState(relayState)
    //				.id(authnRequest.getID())
    //				.build();
    //		}
    //		else {
    //			String xml = serialize(authnRequest);
    //			String deflatedAndEncoded = Saml2Utils.withDecoded(xml).deflate(true).encode();
    //			Saml2RedirectAuthenticationRequest.Builder builder = Saml2RedirectAuthenticationRequest
    //				.withRelyingPartyRegistration(serviceProviderRegistration)
    //				.samlRequest(deflatedAndEncoded)
    //				.relayState(relayState)
    //				.id(authnRequest.getID());
    //			if (serviceProviderRegistration.getAssertingPartyMetadata().getWantAuthnRequestsSigned()
    //					|| serviceProviderRegistration.isAuthnRequestsSigned()) {
    //				Map<String, String> signingParameters = new HashMap<>();
    //				signingParameters.put(Saml2ParameterNames.SAML_REQUEST, deflatedAndEncoded);
    //				if (relayState != null) {
    //					signingParameters.put(Saml2ParameterNames.RELAY_STATE, relayState);
    //				}
    //				Map<String, String> query =
    // this.saml.withSigningKeys(serviceProviderRegistration.getSigningX509Credentials())
    //
    //	.algorithms(serviceProviderRegistration.getAssertingPartyMetadata().getSigningAlgorithms())
    //					.sign(signingParameters);
    //				builder.sigAlg(query.get(Saml2ParameterNames.SIG_ALG))
    //					.signature(query.get(Saml2ParameterNames.SIGNATURE));
    //			}
    //			return (T) builder.build();
    //		}
    //	}
}
