FROM golang:alpine as build

WORKDIR /app

COPY . .

RUN go build -o jwks cmd/main.go

FROM scratch  
COPY --from=build /app/jwks /bin/
ENV PORT=80
ENTRYPOINT [ "/bin/jwks" ]

