# Deploy Edrys to [Deno.land](https://Deno.land)

Minimal steps to reproduce:

1. Visit https://deno.land - create a free account and sign in.

2. Create a "New Project"

3. Select a GitHub repository that contains an edrys fork.

4. Select a branch that contains a compiled dist folder, select __Automatic__, and then select the build-file (`dist/app.js`).

5. Add a unique name

6. And "Add Env Varibles":
  
   1. `EDRYS_SERVE_PATH`: `dist/static`
   2. `EDRYS_DATA_ENGINE`: `memory` for basic testing, otherwise use `s3` in combination with S3-settings from section [Deployment](../Deployment.md#data-storage) or `kv`
   3. `EDRYS_SECRET`: `random-value-secret`

7. Click on "Link"
8. And your project should be deployed ...