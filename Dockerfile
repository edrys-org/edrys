FROM denoland/deno:latest

WORKDIR /

COPY . ./

CMD ["run", "-A", "dist/app.js", "--address", "0.0.0.0:8000", "--serve-path", "dist/static"] 
