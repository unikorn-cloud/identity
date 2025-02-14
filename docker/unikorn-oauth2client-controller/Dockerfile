FROM gcr.io/distroless/static:nonroot

# This is implcitly created by 'docker buildx build'
ARG TARGETARCH

COPY bin/${TARGETARCH}-linux/unikorn-oauth2client-controller /

ENTRYPOINT ["/unikorn-oauth2client-controller"]
