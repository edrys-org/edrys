FROM node:16 AS c-build
WORKDIR /app
COPY client .
RUN npm install
RUN npm run generate

FROM denoland/deno:latest AS s-build
WORKDIR /
COPY server server
RUN deno bundle --unstable server/app.ts /app.js

FROM denoland/deno:latest
WORKDIR /
COPY --from=c-build /app/dist /dist/static
COPY --from=s-build /app.js /dist/
EXPOSE 8000/tcp
CMD ["run", "-A", "dist/app.js", "--address", "0.0.0.0:8000", "--serve-path", "dist/static"]
