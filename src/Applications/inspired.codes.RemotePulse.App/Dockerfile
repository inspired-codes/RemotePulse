FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

COPY ["src/Applications/inspired.codes.RemotePulse.App/inspired.codes.RemotePulse.App.csproj", "src/Applications/inspired.codes.RemotePulse.App/"]
COPY ["src/Shared/inspired.codes.RemotePulse.Shared.Cryptography/inspired.codes.RemotePulse.Shared.Cryptography.csproj", "src/Shared/inspired.codes.RemotePulse.Shared.Cryptography/"]

RUN dotnet restore "src/Applications/inspired.codes.RemotePulse.App/inspired.codes.RemotePulse.App.csproj"

COPY src/ src/
WORKDIR "/src/src/Applications/inspired.codes.RemotePulse.App"
RUN dotnet publish "inspired.codes.RemotePulse.App.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM caddy:2-alpine AS final
COPY --from=build /app/publish/wwwroot /srv
COPY src/Applications/inspired.codes.RemotePulse.App/Caddyfile /etc/caddy/Caddyfile

# Unprivileged, high port, no state: the run configs add a read-only root filesystem, drop all
# capabilities and set no-new-privileges. The official binary ships with cap_net_bind_service as a
# file capability, which the kernel refuses to exec once the capability is dropped; port 8080
# doesn't need it. The edge proxy reaches this as web:8080.
RUN apk add --no-cache libcap-setcap && setcap -r /usr/bin/caddy && apk del libcap-setcap
USER 65532:65532
EXPOSE 8080
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
