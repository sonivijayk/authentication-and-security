# OpenID Connect Extended Authentication Profile (EAP) – A Technical Guide for Phishing-Resistant Authentication


## Background

**Have you ever wondered why your bank, digital wallets or healthcare provider is asking you to enroll into passkey? Let me explain it -**  

With the increasing prevalence of phishing attacks, organizations are enhancing user authentication methods in the risk based authentication processes. Over the last couple of years, OpenId Foundation OpenID published Connect Extended Authentication Profile aka. EAP standard and interoperable solution which allows Relying Parties to confidently request and validate phishing-resistant, hardware-backed authentication using industry adoped mehods like FIDO2/WebAuthn.

EAP profile in authentication workflows significantly elevates security and trust, especially in applications processing sensitive transaction e.g. account linking in healthcare, payment systems, and banking platforms.


In this article I will try to explain - 

- What Is the EAP ACR Values 1.0?
- Example Technical Implementation using FIDO/WebAuthn
- Example EAP Application Use Cases 
- Security & Privacy Considerations
- EAP Profile Deployment Considerations

---

## What Is the EAP ACR Values 1.0?

In Mar 2023,  OpenId Foundation published OpenID Foundation Final Specification introduces two new standardized `acr` (Authentication Context Class Reference) values:

| ACR Value | Description |
|-----------|---------|
| `phr`     | Phishing-Resistant Authentication |
| `phrh`    | Phishing-Resistant + Hardware-Protected Credential |

It also introduces one new `amr` (Authentication Method Reference) value:

| AMR Value | Description |
|-----------|---------|
| `pop`     | Proof-of-Possession of a key |

These values are used in OpenID Connect flows to negotiate or assert stronger authentication context between Relying Party and OpenId based Identity Provider.

---

##  Example Technical Implementation using FIDO/WebAuthn

Let’s walk through a WebAuthn-backed OpenID Connect authentication scenario.


In this scenario (below) /authorize request tells the OpenID Provider (OP) to use a hardware-backed phishing-resistant method.

### Step 1: Relying Party Initiates Authentication Request

````http
GET https://idp.open-id-auth-server/oauth/v1/authorize?
response_type=code&
client_id=test-client-id&
scope=openid profile email&
redirect_uri=https://mysecureapp.com/callback&
acr_values=phrh&
state=sx35ea2107fea12a&
nonce=set3wsxfe54s2233
````

### Step 2: Identity Provider Handles Authentication

The OpenID Provider must:

- Map `acr_values=phrh` to a WebAuthn/FIDO2 ceremony
- Prompt the user to authenticate using a registered FIDO2 credential
- Ensure that:
  - Credential is resident and user-verified
  - Authenticator is bound to hardware

```` java
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AuthenticationContextClassReference;
import com.nimbusds.openid.connect.sdk.claims.ClaimsRequest;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import java.net.URI;
import java.util.List;

public class EAPV1Validator {

    public AuthenticationRequest generateAuthenticationRequest(
            URI authorizationEndpoint,
            ClientID clientID,
            URI redirectURI,
            List<String> registeredCredentialIds) {

        // Define the required ACR values
        ACR acrValue = new ACR("phrh");

        // Build user verification claims request object 
        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("acr", acrValue);

        // Build the authentication request
        return new AuthenticationRequest.Builder(
                new com.nimbusds.oauth2.sdk.ResponseType("code"),
                new com.nimbusds.oauth2.sdk.Scope("openid", "profile", "email"),
                clientID,
                redirectURI)
            .endpointURI(authorizationEndpoint)
            .acrValues(List.of(acrValue)) // Specify the required ACR value
            .claims(claimsRequest) // Include claims for ACR validation
            .customParameter("allowCredentials", String.join(",", registeredCredentialIds)) // Pass registered credentials
            .customParameter("userVerification", "required") // Enforce user verification
            .build();
    }
}
````


### Step 3: Token Issuance with ACR/AMR Claims

Here The Relying Party verifies that `acr = phrh` was met using idToken param acr, amr. See example idToken claims below  

```json
{
  "sub": "userId-of-user",
  "acr": "phrh",
  "amr": ["pop", "fido"],
  "auth_time": 1749358800,
  "iss": "https://idp.open-id-auth-server.com",
  "aud": "my-client",
  "exp": 1749445199,
  "iat": 1749358800,
  "state": "sx35ea2107fea12a",
  "nonce": "set3wsxfe54s2233",
  "name": "Test User",
  "email": "user@email.com",
  "email_verified": true
}

```

where: 
- **sub :**  Authenticated user's unique Id
- **acr :** Authentication Context Class Reference e.g. phrh
- **amr :** Authentication Method Reference e.g. fido
- **auth_time :** User authentication timestamp (Unix epoch format)
- **iss :** idToken issuer or Identity Provider Id or host domain
- **aud :** Token audience, client Id or host domain of Relying Party
- **exp :** Token expiration time in Unix epoch format
- **iat :** Token issuance time in Unix epoch format
- **state :** Unique authentication session identifier, can be used to protect integrity of session
- **nonce :** Random value to prevent replay attacks, same as supplied in the /authorize request
- **name :** User's full name as requested in scope
- **email :** User's email address as requested in scope
- **email_verified :** Boolean indicator to confirm if the user's email address has been verified

---

## Example EAP Application Use Cases 


* **Government Portals :** Government enables EAP profile to allow citizen login
* **Healthcare Portals :** Healthcare provider enable EAP profile to protect medical record access
* **Fintech Applications :** Secure authentication of app user e.g. Open Banking Account Linking
* **e-Commerce :** Cardholder Risk Based Authentication during e-commerce payment transaction 

---

## Security & Privacy Considerations

 **1. Phishing Resistance :**
  - EAP enforces the use of phishing-resistant authentication methods e.g. FIDO2/WebAuthn methods rely on public key cryptography for integrity and trust.
  - Private key of the user never leaves the user's device, making it impossible for attackers to intercept or exploit it

**2. Replay Protection :**
  - Authentication requests under EAP include unique, one-time challenges (nonces) that prevent replay attacks. Even if an attacker intercepts the authentication data, it cannot be reused because the challenge is valid only for a single session. In addition to nonce, I recommend using state value in the idToken to allow end to end unique session integrity 
  - This ensures that authentication remains secure even in the presence of network-level threats.

**3. Device Binding :**
  - EAP requires credentials to be bound to specific hardware devices e.g your mobile phone or laptop, ensuring that authentication can only occur on the registered device.
  - This hardware-backed binding leverages secure elements (e.g., TPMs, Secure Enclaves) on mobile devices and laptops to protect private keys, adding an additional layer of security.
  - Device binding also ensures that credentials cannot be exported or cloned to unauthorized devices.

These considerations make EAP a highly secure and privacy-preserving standard, suitable for sensitive applications such as banking, healthcare, and payment systems.

---

## EAP Profile Deployment Considerations

When deploying the EAP based security, it is essential to follow these considerations to ensure a secure and seamless user experience:

1. **Validate `acr` in idToken**:
   - `acr` value in the idToken must be validated to confirm that the authentication meets the required assurance level e.g. `phr` or `phrh`
   - This ensures that the authentication performed by the Identity Provider (IdP) aligns with the security requirements of the Relying Party (RP)
   - Failure to validate the `acr` value could result in weaker authentication being accepted, compromising security
2. **Ensure IdP Supports EAP**:
   - Verify that the Identity Provider (IdP) supports the EAP standard and can handle requests with `acr_values` such as `phr` or `phrh`
   - Identity Provider (IdP) must be capable of mapping these values to appropriate phishing-resistant and hardware-backed authentication methods, such as FIDO2/WebAuthn
   - If the IdP does not support EAP, the authentication flow will not meet the desired security guarantees

3. **Register EAP-Specific Clients**:
   - Relying Parties (RPs) must register clients specifically configured to use EAP with the IdP
   - During client registration, ensure that the `acr_values` required for EAP are explicitly declared and supported
   - This step ensures that the IdP enforces the correct authentication policies for the registered client

4. **Enable WebAuthn Discoverable Credentials**:
   - WebAuthn discoverable credentials (also known as resident credentials) should be enabled to simplify the user experience and enhance security
   - Discoverable credentials allow users to authenticate without needing to select a credential manually, as the authenticator can automatically identify the correct one
   - This feature is particularly useful for multi-device scenarios and ensures that credentials remain bound to the user's hardware


---

## Conclusion

With a simple `acr_values=phrh`, RPs can enforce advanced security postures. Whether you’re a financial app, government platform, or health system, adoption