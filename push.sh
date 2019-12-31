docker build -t traefik-azure -f exp.Dockerfile .
docker tag traefik-azure:latest nabeel01/traefik-azure:$1
docker push nabeel01/traefik-azure:$1
