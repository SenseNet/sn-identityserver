#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/core/aspnet:3.0-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.0-buster AS build
WORKDIR /src
COPY ["SenseNet.IdentityServer4.Docker.sln", "."]
COPY ["SenseNet.IdentityServer4/SenseNet.IdentityServer4.csproj", "SenseNet.IdentityServer4/"]
COPY ["SenseNet.IdentityServer4.Web/SenseNet.IdentityServer4.Web.csproj", "SenseNet.IdentityServer4.Web/"]
RUN dotnet restore "SenseNet.IdentityServer4.Docker.sln"
COPY . .
#RUN ls SenseNet.IdentityServer4.Web
RUN dotnet build "SenseNet.IdentityServer4.Docker.sln" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "SenseNet.IdentityServer4.Docker.sln" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SenseNet.IdentityServer4.Web.dll"]
