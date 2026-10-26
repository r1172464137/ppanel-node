# Build go
FROM golang:1.27.3-alpine AS builder
WORKDIR /app
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN apk add --no-cache bash curl
RUN go mod download
RUN go build -v -o ./output/ppnode -trimpath -ldflags "-X github.com/perfect-panel/ppanel-node/cmd.version=${VERSION} -s -w -buildid="
RUN bash scripts/fetch-geodata.sh ./output/geodata

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir -p /etc/PPanel-node/ /usr/local/PPanel-node/
COPY --from=builder /app/output/ppnode /usr/local/PPanel-node/ppnode
COPY --from=builder /app/output/geodata/geoip.dat /app/output/geodata/geosite.dat /app/output/geodata/geodata.lock /usr/local/PPanel-node/
WORKDIR /usr/local/PPanel-node

ENTRYPOINT [ "/usr/local/PPanel-node/ppnode", "server", "--config", "/etc/PPanel-node/config.yml"]
