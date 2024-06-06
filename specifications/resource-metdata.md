# Resource Metadata Specification

Resources are indexed by Kubernetes name.
This led to a few useful traits provided by the underlying platform:

* Naming conflict resolution
* Forcing users to treat resources like cattle as names are immutable.
* Human readable resource names can be propagated as metadata to other components e.g. cloud provider tags, as they are guaranteed not to change

However there were also some drawbacks:

* Resource names are tied to Kubernetes (DNS) syntax e.g. 63 characters, a-z, 0-9 etc.
* Resources names are immutable, doing so would be akin to deletion and recreation (see the above point about cattle)

This proposal aims to provide a formal specification that allows the best user experience possible, while yielding simple and reusable software and also not impeding support processes to the extent that it's likely that mistakes will be made.

## Changelog

- v1.0.0 2024-05-29 (@spjmurray): Initial RFC
- v1.0.1 2024-06-06 (@spjmurray): Update to mirror reality

## Considerations

### Generic Metadata

Every resource in the system should have the following items, unless where specified.

#### Unique Identifier

The resource ID maps to a Kubernetes name, so will still be governed by DNS labels, but also critically compatible with HTTP path segments for use as IDs.
The proposal is to use Kubernetes name generation to inject 5 characters of entropy into resource names, and prefix them with the resource type.

Because of this, the requirement of namespaces is lifted, e.g. organizations don't need a namespace to separate projects from another organization.
The logical separation that namespaces gives us is still relevant however, in that we can use namespaces to limit scope in a far safer way than using labels alone.

#### Resource Name

This is a free-form Unicode string that doesn't have any of the limitations of a DNS label, it can include spaces, punctuation and even i18n.

We do sacrifice the simplicity of having Kubernetes names detect conflicts.
Clients *should* check this before hand anyway to provide real time feedback, however we will now need to build explicit checks into the API endpoints too.

Storing resource names as labels does allow us to lookup, at the API level, a named resource, but the preference will be to perform discovery via a GET operation against the resource collection endpoint, and other operations against the individual resource endpoint using an ID derived from the initial GET.

Using labels limits the character set to that defined [by Kubernetes](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set).
Annotations on the other hand allow arbitrary text (e.g. it was used for a long time to store JSON for `kubectl apply`).
Annotations do however suggest the metadata is non-identifying, and cannot be used to index a resource, which makes resource ID _the_ de facto identifier at the API level.

#### Resource Description **OPTIONAL**

The description should be a verbose description of what the resource is for, useful where names have a specific schema, that is non-intuitive, and you want to give additional detail to viewers so they don't accidentally delete something.

#### Creation and Deletion Time

Creation time is useful to see the age of a resource, and offers the ability to sort by age to better locate a resource in a client.

The deletion time is an indication that resource deletion has been requested, and thus other calls to edit or delete the resource should be inhibited to avoid false negative errors.

#### Provisioning Status

Typically this maps directly from a Kubernetes status condition, but to future proof things we should make it generic so we can add health monitoring to any resource trivially in future even if it doesn't have a Kubernetes controller.
This makes client handling far simpler.

By making this explicitly about provisioning, we can extend the metadata further with asynchronous health checks further down the line.

### Scoped Metadata

Historically, we've been lazy, in the sense that a GET against a collection endpoint returns everything that is in scope, typically within an organization.
This facilitates a global view of everything in the organization, particularly relevant to administration views.
Any more constrained view can be achieved by further scoping the data client-side by using the following metadata items.

#### Organization and Project

Presently, the organization is implicit as all relevant API resource endpoints are nested under an organization, but we can anticipate future views that take into consideration the entire platform e.g. to check an upgrade succeeded across all organizations.

The project allows resources to be grouped per-project for easy display of hierarchical constructs, and allowing roll-up of data into per project summaries an the client side.

Note that at present this is all keyed to the resource name, and will need to be migrated to unique IDs.

## Modeling Metadata

### GET Requests

Generic metadata should look like the following:

```yaml
components:
  schemas:
    resourceProvisioningStatus:
      type: string
      enum:
      - unknown
      - provisioning
      - provisioned
      - deprovisioning
      - error
    resourceMetadata:
      type: object
      required:
      - name
      - description
      properties:
        name:
          type: string
        description:
          type: string
    resourceReadMetadata:
      allOf:
      - $ref: '#/components/schemas/resourceMetadata'
      - type: object
        required:
        - id
        - creationTime
        - provisioningStatus
        properties:
          id:
            type: string
          creationTime:
            type: string
            format: date-time
          deletionTime:
            type: string
            format: date-time
          provisioningStatus:
            $ref: '#/components/schemas/resourceProvisioningStatus'
```

Scoped metadata would look like the following.
Note the use of inheritance to create a hierarchy.

```yaml
components:
  schemas:
    organizationScopedResourceReadMetadata:
      allOf:
      - $ref: '#/components/schemas/resourceReadMetadata'
      - type: object
        required:
        - organizationId
        properties:
          organizationId:
            type: string
    projectScopedResourceReadMetadata:
      allOf:
      - $ref: '#/components/schemas/organizationScopedResourceReadMetadata'
      - type: object
        required:
        - projectId
        properties:
          projectId:
            type: string
```

A typical resource specific schema will look like:

```yaml
components:
  schemas:
    kubernetesclusterRead:
      type: object
      required:
      - metadata
      - spec
      properties:
        metadata:
          $ref: '#/components/schemas/projectScopedResourceReadMetadata'
        spec:
          # resource specific stuff goes here.
```

### POST and PUT Requests

Generic metadata should look like the following:

```yaml
components:
  schemas:
    resourceWriteMetadata:
      $ref: '#/components/schemas/resourceMetadata'
```

This quite clearly makes a distinction between mutable fields that can be written by a client, and read-only fields that are controlled by the server.

Through the magic of duck-typing, `resourceReadMetadata` *could* be used directly as a `resourceWriteMetadata`, although that will just result in the server rejecting the request as it doesn't conform to the schema.

A typical resource specific schema will look like:

```yaml
components:
  schemas:
    kubernetesclusterWrite:
      type: object
      required:
      - metadata
      - spec
      properties:
        metadata:
          $ref: '#/components/schemas/resourceWriteMetadata'
        spec:
          # resource specific stuff goes here.
```

From a client viewpoint, as regards PUT update operations, the metadata needs to be converted from the read version to the write version, then mutated as necessary, the specification can be copied verbatim.

## CI/CD Driver Considerations

When creating applications, the CI/CD driver typically creates a composite key of `${organization}/${project}/${resource}/${application}` to yield a unique fully qualified name for the application and other primitives like remote clusters.

These typically appear as either a name directly, or as labels that are indexed and can be queried in the CD tooling.
As these fields are presently resource names, we can very quickly locate a specific troublesome application based on the organization, project and resource (e.g. cluster) name.

Sadly as names are mutable now, we lose this ability as the fully qualified name would be composed of resource IDs, making lookups in the event of a support request both painfully slow and prone to human error as you have to translate between a logical name and a physical one.

We *could* propagate contextual naming information to resources, and then on to applications to restore this functionality, but that is added complexity, and will cause unnecessary reconciliation for simple metadata changes.
See the next section for further arguments.

## Cloud Platform Considerations

Like CI/CD drivers, we are able to tag cloud infrastructure with metadata that accelerates problem resolution time and reduces maintenance overheads.

Unlike applications, that can be annotated with labels, the tags attached to infrastructure are immutable and implemented by third party applications e.g. Cluster API.
Labels can be changed, but doing so would require a rolling rebuild of the infrastructure to facilitate the change.

Based on this observation, our common denominator is the use of IDs throughout the system.
Operations and support teams will just need to stomach the pain and associated risk that comes with the change.
