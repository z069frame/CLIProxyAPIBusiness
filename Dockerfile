FROM node:20-alpine AS web-builder

WORKDIR /web

COPY web/package.json web/package-lock.json ./

RUN npm ci

COPY web/ ./

RUN npm run build

FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

COPY --from=web-builder /web/dist ./internal/webui/dist

RUN CGO_ENABLED=0 GOOS=linux go build -o ./cpab ./cmd/business/

FROM alpine:3.22.0

RUN apk add --no-cache tzdata

RUN mkdir /CLIProxyAPIBusiness

COPY --from=builder ./app/cpab /CLIProxyAPIBusiness/cpab

WORKDIR /CLIProxyAPIBusiness

EXPOSE 8318

ENV TZ=Asia/Shanghai

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

CMD ["./cpab"]
