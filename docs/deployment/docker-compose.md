# docker-compose

This is an example of a `docker-compose.yml` that can be used to host edrys.

``` yaml
version: '3'
services:
  edrys:
    image: edrys/edrys
    ports:
      - "8000:8000"
    environment:
      #- EDRYS_SECRET=
      #- EDRYS_SMTP_TLS=true
      #- EDRYS_SMTP_HOST=
      #- EDRYS_SMTP_PORT=465
      #- EDRYS_SMTP_USERNAME=
      #- EDRYS_SMTP_FROM=
      #- EDRYS_SMTP_PASSWORD=
    volumes:
      - data:/.edrys

volumes:
  data:
```


Copy and paste this content into a local `docker-compose.yml`, change your settings and then execute:

`docker-compose up`