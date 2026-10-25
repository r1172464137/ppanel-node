# Build go
FROM golang:1.27.3-alpine AS builder
WORKDIR /app
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN go mod download
RUN go build -v -o ./output/ppnode -trimpath -ldflags "-X github.com/perfect-panel/ppanel-node/cmd.version=${VERSION} -s -w -buildid="

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/PPanel-node/
COPY --from=builder /app/output/ppnode /usr/local/bin

ENTRYPOINT [ "ppnode", "server", "--config", "/etc/PPanel-node/config.yml"]
