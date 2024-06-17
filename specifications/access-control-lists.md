# Access Control List Specification

Access control lists form the basis of role based access control (RBAC), and provide a generic interface that can can be consumed by services to lock down API endpoints.

The identity service provides a number of primitives that scope access:

* organizations provide administrative boundaries and control the set of users that are considered part of that organization.
* projects exist within an organization and provide multi-tenancy within the organization.

Projects control access by granting access to groups of users, and those groups in turn define roles that a user has.
This specification describes how this authorization information is propagated from the identity service to individual services.

## Changelog

- v1.0.0 2024-07-02 (@spjmurray): Initial RFC

## Primitives

### Operation Types

These are based on CRUD and define the operation type that is allowed as follows:

* **Create** is the ability to create a resource
* **Read** is the ability to read a single resource or a collection
* **Update** is the ability to modify a resource
* **Delete** is the ability to delete a resource

These scope types can be combined into arbitrary sets to facilitate a business function for example:

* **R** means you can discover and use resources but cannot make any modifications, e.g. an auditor or infrastructure consumer.
* **RU** means you can discover and us resources, and can make modification, but cannot create or delete, e.g. an operator who requires permission to create new OPEX costs, and isn't allowed to delete mission critical infrastructure.

### Operation Resources

These can be thought of as fine-grain types of things that operation types can be applied to:

* **Groups** allow users to see groups in order to associate them with projects
* **Projects** allow users to see projects in order to create clusters in them

Resource types must be arbitrary as other services can define their own.

### Operation Scopes

Some resources will exist at the organization level, whereas some may be assigned on a per-project basis:

* **Groups** exist for the organization as do **Projects**
* **Regions** may be global or may belong to a specific organization, and can be used by anyone in that organization, or may belong to a specific project so only users in a group linked to that project can use them

## Resource Scoping

It is often desirable to get a view across the entire organization of a particular resource e.g. how much is the organization as a whole consuming.
It is also more efficient making a single API call that multiple i.e. project discovery and resources scoped to different projects.
For this reason the identity service should be able to communicate this information in a succinct and simple data structure that is conducive to fast and robust algorithms.

Additionally, by breaking down scopes by project, any endpoint RBAC can trivially reject requests with only a single call to retrieve that data structure.

## Access Control Lists

Consider the following data-structure:

```yaml
superAdmin: false
organization:
  id: a4726815-d2b9-4a4b-8a01-3299810c59c4
  scopes:
  - name: groups
    operations: [read]
  - name: projects
    operations: [create, read, update, delete]
projects:
- id: e7b0c825-4524-422f-ae43-0818ef8c45bc
  scopes:
  - name: infrastructure
    operations: [create]
  - name: kubernetesclusters
    operations: [create, read, update, delete]
signature: VGhpcyBpcyBhIGRpZ2l0YWwgc2lnbmF0dXJlIQ==
```

The **superAdmin** property grants access to do and see everything across the platform, any other configuration (besides the `signature` is irrelevant.

The **organization** property defines the organization this ACL is scoped against.
This allows RBAC to check that the ACL corresponds to the API request and we're not using the wrong data.
So to access the Identity service's organization groups, RBAC would first check the ID matches that supplied as the _organizationID_ parameter, then that the _groups_ resource is specified, then the _read_ operation.

The **project** property defines access scopes for specific named projects.
To create a Kubernetes cluster you would first check the _organizationID_ parameter matches the ACL organization, then check the _projectID_ parameter exists in the project scopes, then finally check the correct resource and operation exist.

The **signature** is there to verify message integrity and prevent MitM attacks from performing privilege escalation.
To generate, the signature the message without the `signature` property is canonicalized as defined by [JCS](https://datatracker.ietf.org/doc/html/rfc8785), a digest is calculated with SHA256 then signed with ECDSA using the identity service's private key.
To verify, follow the same canonicalization and digest rules, then verify ECDSA signature.

### ACL Use

Primarily this data is used as described earlier to control top level endpoint access though calls like:

```go
func HandleCreateGroup(w http.ResponseWriter, r *http.Request, organizationID string) {
	if err := rbac.AllowOrganizationScoped(r.Context(), "groups", rbac.Create, organizationID);
 err != nil {
                // reject
        }
}

func HandleReadClustersProjectScoped(w http.ResponseWriter, r *http.Request, organizationID, projectID string) {
	if err := rbac.AllowProjectScoped(r.Context(), "clusters", rbac.Read, organizationID, projectID); err != nil {
		// reject
	}
}
```

> [!NOTE]
> The ACL will the made available via the authentication middleware and saved to the request context.

It can also be used to scope resources as described earlier:

```go
func HandleReadClustersOrganizationScoped(w http.ResponseWriter, r *http.Request, organizationID string) {
	// API level RBAC here as above

	// Read and apply scoping.
	selector := []string{
		"organizationID=" + organizationID,
		"projectID in (" + strings.Join(rbac.GetACL(r.Context()).Projects(rbac.Read), ",") + ")",
	}

	resources := &ClusterList{}

	if err := client.List(r.Context(), &resources, Options{LabelSelector: selector}); err != nil {
		// handle error
	}

	writeResponse(w, resources)
}
```

The final intent is for the ACL to be used to drive client interactions e.g. can I create a cluster in this project?
If so then show the create button/dialog.

> [!NOTE]
> ACLs _MAY_ be cached by a client to reduce API traffic to the identity service and improve request latency.
> The obvious side effect here is you will need to wait before RBAC rule updates are picked up by cache expiry, but it is worth considering.

## API Considerations

Taking the oauth2 provider resource as an example, we provide some global providers e.g. Google and Microsoft, and the user can defined their own.
While we could return the union in a single call for organization scoped providers, this would have the knock on effect that we would be returning global client IDs and secrets if we didn't do some response type filtering based on resource scope.
In this instance it's prudent to have two separate APIs with different schemas for the different use cases.

Consider regions, on the other hand, that don't feature any sensitive information, in this case it is safe to combine global, organization and project scoped regions together to reduce API interaction.

We should avoid having to treat data specially in different contexts to improve reliability and security, but optimize for performance where possible.

## Kubernetes API

The following role definition should cover all bases:

```yaml
apiVersion: identity.unikorn-cloud.org/v1alpha1
kind: Role
metadata:
  name: f0b37da2-6ac1-47a6-b54d-40f1336629a0
  labels:
    unikorn-cloud.org/name: Organization Administrator
spec:
  scopes:
    global:
    - name: oauth2providers
      operations: [read]
    organization:
    - name: oauth2providers
      operations: [create, update, read, delete]
    - name: groups
      operations: [create, update, read, delete]
    - name: projects
      operations: [create, update, read, delete]
    project:
    - name: infrastructure
      operations: [create, update, read, delete]
    - name: kubernetesclusters
      operations: [create, update, read, delete]
```

When building the ACL we:

* List all groups in the organization
  * Select only the groups that the user is a member of
  * For each group, add any global scoped resource permissions to the ACL
  * For each group, add any organization scoped resource permissions to the ACL
* List all projects in the organization
  * Select only the projects that have access granted to any of the selected groups
  * For each project, add any project scoped resource permissions to that project in the ACL
* Sign the ACL

> [!NOTE]
> You may have multiple roles that contain the same organization scopes with different permissions.
> Likewise you may have multiple project roles that contain the same project scopes with different permissions.
> In either case, the permissions are additive i.e. a Boolean union.
