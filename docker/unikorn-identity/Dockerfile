FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

# Required as we are talking to Openstack public endpoints.
COPY bin/${TARGETARCH}-linux/unikorn-identity /

ENTRYPOINT ["/unikorn-identity"]
