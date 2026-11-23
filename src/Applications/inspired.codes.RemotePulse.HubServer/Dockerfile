# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /source

# Copy everything and restore the solution
COPY . .
RUN dotnet restore src/Applications/inspired.codes.RemotePulse.HubServer/inspired.codes.RemotePulse.HubServer.csproj

# Publish the Hub project
RUN dotnet publish src/Applications/inspired.codes.RemotePulse.HubServer/inspired.codes.RemotePulse.HubServer.csproj -c Release -o /app --no-restore

# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS final
WORKDIR /app
COPY --from=build /app .
EXPOSE 8080
ENTRYPOINT ["dotnet", "RemotePulse.HubServer.dll"]
