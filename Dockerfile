FROM denoland/deno:latest

WORKDIR /

COPY . ./

CMD ["run", "-A", "dist/app.js", "--address", "localhost:8000", "--serve-path", "dist/static"] 
