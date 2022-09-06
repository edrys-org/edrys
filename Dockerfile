FROM denoland/deno:latest
WORKDIR /
COPY . ./
EXPOSE 8000/tcp
CMD ["run", "-A", "dist/app.js", "--address", "0.0.0.0:8000", "--serve-path", "dist/static"] 
