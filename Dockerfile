FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Install NativeAOT build prerequisites
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       clang zlib1g-dev

WORKDIR /App

# Copy everything
COPY ./src ./

# Restore as distinct layers
RUN dotnet restore

# Build and publish a release
RUN dotnet publish -c Release -o build -r linux-musl-x64 --self-contained true /p:PublishAot=true

# Build runtime image
FROM alpine:3.23.3
LABEL org.opencontainers.image.source=https://github.com/Sajidur78/Garde
LABEL org.opencontainers.image.description="Garde Authenticator"
LABEL org.opencontainers.image.licenses=MIT-0

RUN apk add libc6-compat

WORKDIR /App
COPY --from=build /App/build .
ENTRYPOINT [ "./Garde" ]