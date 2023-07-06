all: client deno

client:
	cd client && npm run generate && rm -rf ../dist/static && cp -r dist ../dist/static

deno:
	deno bundle server/app.ts dist/app.js

run:
	deno run -A dist/app.js --address localhost:8000 --serve-path dist/static --secret 182761552627328716