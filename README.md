# Unikorn Identity

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

Unikorn's Identity Provider.
This package provides an OIDC compliant server, that federates other OIDC compliant backends.

Users are designed to be ephemeral, thus requiring no state management, no databases and result in a coponent that can be horizontally scaled trivially.

## Architecture

![Resource](./docs/images/resources.png)

Conceptually, the identity service is quite simple, but does feature some enterprise grade features, described in the following sections.

### Organizations

The top level resource type is an organization.
Organziations are indexed via name, the name must be unique across the system, and is limited by normal Kubernetes resource name semantics (i.e. a DNS label).

Organizations MAY define a domain e.g. `acme.com`.
This allows users to login via email address where one of the generic IdP backends does not suffice, or the user isn't aware of who is providing identity services.
By spceifiying a domain, any user whose email domain matches a registered organization domain will be routed to the correct IdP configured for the organization.
This allows the use of a custom IdP that is not Google Identity (Google Workspace) or Microsoft Entra (Office 365), for example Okta or Authentik.

### oauth2 Providers

The identity service provides some generic providers, Google, and Microsoft, which covers the vast majority of many organizations.

You can _bring your own_ by providing:

* And OIDC compliant issuer endpoint
* A client ID
* A client secret

Providers may have a supported driver build into the identity service that allows groups to be read from the identity provider for use in group mapping.

### Groups

Every organization SHOULD have some groups, as it's useless without them.
Groups define a set of users that belong to them, and a set of roles associated with that group.

Users can be included explicitly, implicitly, or a mixture of both.
Explicit users are simply added to a list within the group, the user name MUST be the user's canonical name (as returned by the _id\_token_ after authentication), and not an alias.
Implicit users are defined by an identity provider group, and are generally easier to govern for large organization.

There are no constraints on which users can belong to any group, thus enabling - for example - an external contractor to be added, or a user to be a member of multple organizations.

When a user is part of an organization group, it can discover that organization.
Any user is not part of an organization will be denied entry to the system, and require either adding to a new organization via a back-channel (e.g. customer onboarding), or adding by an organization admin.

### Roles

Every group SHOULD have at last one role.

We define a number of default roles, but the system is flexible enough to have any arbitrary roles.

The `admin` role allows broad access across the organization, it can edit organizations, create roles and associate users with them, and create projects and associate groups with them.
Admin users can generally see all resources within the organization defined for other services, and manage them.

The `user` role cannot modify anything defined by the identity service, it's only allowed to discover organizations and projects its a member of.
Users SHOULD have additional permissions defined for external services, e.g. provisioning and management of compute infrastructure.

The `reader` is similar to the `user` but allows read only access, typically used by billing and auditing teams.

### Projects

Projects provide workspaces for use by external services.
Projects are visible to all `admin` users.
Other users are included in a project by associating it with a group, therefore each project SHOULD have at least one group associated with it.

Like most other components, flexibility is built in by design, so a project can be shared with multiple groups.
