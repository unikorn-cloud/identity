# Unikorn Identity

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

Unikorn's Identity Provider.
This package provides an OIDC compliant server, that federates other OIDC and oauth2 compliant backends.

## Architecture

![Resource](./docs/images/resources.png)

Conceptually, the identity service is quite simple, but does feature some enterprise grade features, described in the following sections.

### Organizations

The top level resource type is an organization.
Organizations are indexed via name, the name must be unique across the system, and is limited by normal Kubernetes resource name semantics (i.e. a DNS label).

Organizations MAY define a domain e.g. `acme.com`.
This allows users to login via email address where one of the generic IdP backends does not suffice, or the user isn't aware of who is providing identity services.
By specifying a domain, any user whose email domain matches a registered organization domain will be routed to the correct IdP configured for the organization.
This allows the use of a custom IdP that is not Google Identity (Google Workspace) or Microsoft Entra (Office 365), for example Okta or Authentik.

### oauth2 Providers

The identity service provides some generic providers, Google, and Microsoft, which covers the vast majority of many organizations.

You can _bring your own_ by providing:

* And OIDC compliant issuer endpoint
* A client ID
* A client secret

Providers may have a supported driver build into the identity service that allows groups to be read from the identity provider for use in group mapping.

By default Unikorn Identity supports:

* Google Workspace
* Microsoft Entra
* GitHub

### Users

Users are records that record a user in the system.
Rather than allow ephemeral users directly from federated identity provider, these records allow more flexibility in user handling.
For example, they can record a user's status, where by they can be disabled (without disassociating any group memberships, but they aren't allowed access to the organization), or in a pending state (to allow email verification).

Further reading:

* [Email Notifications and User Verification](#email-notifications-and-user-verification)

### Groups

Every organization SHOULD have some groups, as it's useless without them.
Groups define a set of users that belong to them, and a set of roles associated with that group.

Users are simply added to a list within the group, the user name MUST be the user's canonical name (as returned by the _id\_token_ after authentication), and not an alias.
Supporting aliases would require intrusive API requests against identity providers to list them.

There are no constraints on which users can belong to any group, thus enabling - for example - an external contractor to be added, or a user to be a member of multiple organizations.

Any user is not part of an organization will be denied entry to the system (Dy default), and require either adding to an organization via a back-channel (e.g. customer onboarding), or adding by an organization admin.

### Roles

Every group MUST have at least one role.

We define a number of default roles, but the system is flexible enough to have any arbitrary roles.

The `admin` role allows broad access across the organization, it can edit organizations, create roles and associate users with them, and create projects and associate groups with them.
Admin users can generally see all resources within the organization defined for other services, and manage them.

The `user` role cannot modify anything defined by the identity service, it's only allowed to discover organizations and projects its a member of.
Users SHOULD have additional permissions defined for external services, e.g. provisioning and management of compute infrastructure.

The `reader` is similar to the `user` but allows read only access, typically used by billing and auditing teams.

> [!NOTE]
> If you do define external 3rd party roles, you will be responsible for removing any references to them from groups on deletion.
> Failure to do so will result in dangling references, an inconsistency and an error condition.

### Projects

Projects provide workspaces for use by external services.
Projects are visible to all `admin` users.
Other users are included in a project by associating it with a group, therefore each project SHOULD have at least one group associated with it.

Like most other components, flexibility is built in by design, so a project can be shared with multiple groups.

## Security

### OIDC Clients

Any compliant OIDC client library should be able to interact with the identity service.
It features service discovery for simple configuration, and the login hint extension for seamless token refresh.

To enable a client, you will need to create a `oauth2client` resource in the identity service namespace, featuring the client ID (must be unique, typically you can use `uuidgen` for this), and an OIDC callback URI.

Optionally you can override the branding with a custom login and error URL callback too.
These are available on the `OAuth2Client` data type.
See the reference implementation [login](https://github.com/unikorn-cloud/ui/tree/main/src/routes/login) and [error](https://github.com/unikorn-cloud/ui/tree/main/src/routes/error) pages for the interface.

### Authentication

Authentication is handled in a few different ways:

* OIDC authorization code flow (for typical users via a browser).
* Service accounts (that issue long lived access tokens).
* System accounts secured by X.509 (used by Unikorn services to talk to one another).

Service endpoints that users directly interact with will use token introspection against he Identity service to authenticate a user, then retrieve and ACL to authorize the request.

Services that act on behalf of an end user will use X.509 to retrieve an access token, then when interacting with downstream services will have that token authenticated and authorized in exactly the same way as with end user tokens.

### RBAC

The identity service provides centralized role based access control to the Unikorn suite of services.
As described previously, roles can be arbitrary and apply to services outside of the identity service.

A role is composed of a set of arbitrary endpoint scopes, that typically define an API endpoint group e.g. `kubernetes:clusters` or `identity:projects`.
Within an endpoint scope is a set of permissions; `create`, `read`, `update` and `delete` (i.e. CRUD).

Endpoint scopes are grouped by identity scopes, `global` scopes affect all resources on the platform, `organization` scopes are limited to an organization and `project` scopes are limited to specific projects.

The API provides access to an access control list (ACL) which contains global scopes, organization scopes for the selected organization, and project scopes within that organization.

The ACL is used to:

* Control API access to endpoint resources.
* Drive UI views tailored to what actions the user can actually perform.

### Scoping

Some APIs e.g. listing Kubernetes clusters within an organization, are implicitly scoped.
These will return all clusters if you have global or organization scoped cluster read access, or only those resources that exist in projects you have cluster read access to.

## Integration with Other Services

By itself, the identity service doesn't offer much functionality beyond simple OIDC authentication flows.
Other services are responsible for provisioning and managing actual resources.

Because this is a multi-tenant system, we need a top level organization to be unique, this is achieved by having these all provisioned in the identity service's namespace.
We do anticipate most users to expect they can provision any cluster name they wish, so these must be provisioned in an organization specific namespace.
Likewise, multiple projects within the same organization may want resources that are named the same in different projects, for example to facilitate different environments, so these need a project specific namespace too.

![Resource](./docs/images/namespaces.png)

The identity service manages all this for you automatically.
Unique namespace names are automatically generated by the platform, and organization and project resources record this in their status for easy navigation.

Other services, e.g. the core Kubernetes service can then consume the project namespace by having their custom resources residing in there, separating them from other projects and other organizations.

## Installation

Identity is the first thing you should install, as it provides authentication services for other services, or can be used as a standalone identity provider.

### Prerequisites

* A domain name (`acme.com` for this tutorial)
* [external-dns](https://github.com/kubernetes-sigs/external-dns) configured on your Kubernetes cluster to listen to `Ingress` resources.
* [cert-manager](https://cert-manager.io/) configured on your Kubernetes cluster
* A cert-manager `ClusterIssuer` configured for use, typically Let's Encrypt, but you can use a self signed CA.

```shell
DOMAIN=acme.com
```

### Configuring an OIDC Backend

First you will need to calculate what the OIDC callback will be.
Choose a public DNS name from your domain e.g. `identity.acme.com`.
The OIDC callback URI will be `https://identity.acme.com/oidc/callback`:

```shell
IDENTITY_HOST=identity.${DOMAIN}
IDENTITY_OIDC_CALLBACK=https://${IDENTITY_HOST}/oidc/callback
```

Most OIDC providers will be configured by creating an "Application".
This will require the callback URI to be registered as trusted.
The identity provider will give you an issuer or discovery endpoint, client ID and client secret for the following steps.

> [!NOTE]
> Only Google Identity, Microsoft Entra and GitHub are currently supported.
> Documentation for individual providers is provided by them.

### Installing the Service with Helm

You must first define where the UI will live in order to configure that OIDC callback and setup CORS:

```shell
UI_HOST=console.${DOMAIN}
UI_ORIGIN=https://${UI_HOST}
UI_OIDC_CALLBACK=${UI_ORIGIN}/oauth2/callback
UI_LOGIN_CALLBACK=${UI_ORIGIN}/login
UI_ERROR_CALLBACK=${UI_ORIGIN}/error
UI_CLIENT_ID=$(uuidgen)
```

Create a basic `values.yaml` file:

```yaml
host: ${IDENTITY_HOST}
cors:
  allowOrigin:
  - ${UI_ORIGIN}
ingress:
  clusterIssuer: letsencrypt-production
  externalDns: true
clients:
  unikorn-ui:
    redirectURI: ${UI_OIDC_CALLBACK}
    homeURI: ${UI_ORIGIN}
    loginURI: ${UI_LOGIN_CALLBACK} # (optional)
    errorURL: ${UI_ERROR_CALLBACK}
providers:
  google-identity:
    description: Google Identity
    type: google # (must be either google or microsoft)
    issuer: https://accounts.google.com
    clientID: <string> # provided by the identity provider, see above
    clientSecret: <string> # provider by the identity provider, see above
platformAdministrators:
  subjects:
  - wile.e.coyote@acme.com
systemAccounts:
  unikorn-kubernetes: infra-manager-service
  unikorn-compute: infra-manager-service
```

Install the Helm repository:

```shell
helm repo add unikorn-identity https://unikorn-cloud.github.io/identity
```

Deploy:

```shell
helm update --install --namespace unikorn-identity unikorn-identity/unikorn-identity -f values.yaml
```

### Email Notifications and User Verification

Identity supports a mode of operation where new user accounts need to be verified before they can be made active.
First you will need to configure SMTP.
Consult your provider on acquiring the server, port, and credentials.

Create a secret containing the credentials:

```shell
kubectl create secret -n unikorn-identity generic --from-literal username=${USERNAME} --from-literal password=${PASSWORD} unikorn-smtp-credentials
```

Next configure your `values.yaml` file to add in the SMTP server information and enable user verification:

```yaml
smtp:
  host: smtp.mail.yahoo.com:465

signup:
  enabled: true
```

### Installing the Management Plugin

Download the following artefacts an install them in your path:

* `kubectl-unikorn`
* `kubectl_complete-unikorn`

### User Onboarding

Typically your deployment will have a small select few engineers who are able to see and do everything, including creating organizations.
At present self-signup is not possible.

In the earlier `values.yaml` manifest, the following section was defined:

```yaml
platformAdministrators:
  subjects:
  - wile.e.coyote@acme.com
```

This forms an implicit mapping from a user to a special role that grants access to all-the-things.

In order to actually login, you will need a user account creating:

```yaml
+kubectl unikorn create user \
     --namespace unikorn-identity \
     --user wile.e.coyote@acme.com
```

If your user's email address can be authenticated by any of the supported OIDC integrations, that's all you need to do, otherwise read on...

#### Creating an Organization and OIDC Integration

> [!NOTE]
> This needs writing and tooling provided.
> If you are brave you can:
> * Create an `organization` with domain scoping.
> * Create an `oauth2provider` in that organization that provides authentication for that domain.

### 3rd Party Service Integration

When using an integration such as the [Unikorn Kubernetes Service](https://github.com/unikorn-cloud/kubernetes) you will need to configure system account to RBAC mappings.
3rd party services usually act on behalf of a user, and as such need elevated global privileges, so as to avoid giving the end user permission to sensitive endpoints.

In the earlier `values.yaml` manifest, the following section was defined:

```yaml
systemAccounts:
  unikorn-kubernetes: infra-manager-service
  unikorn-compute: infra-manager-service
```

In very simple terms, when you create a 3rd party service, that will need to generate an X.509 certifictae in order to authenticate with the tokens endpoint and issue an access token to talk to other Uniorn service APIs.
That certificate will need to be signed by the trusted client CA (typically signed by the `unikorn-client-issuer` managed by cert-manager).
The X.509 Common Name (CN) encoded in the certificate is the key to this mapping e.g. `unikorn-kubernetes`.
The value references a role name that is either installed by default, or created specifically for your service.

## What Next?

As you've noted, objects are named based on UUIDs, therefore administration is somewhat counter intuitive, but it does allow names to be mutable.
For ease of management we recommend installing the [UI](https://github.com/unikorn-cloud/ui)
