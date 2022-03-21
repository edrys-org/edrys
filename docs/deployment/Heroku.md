![heroku-logo](https://upload.wikimedia.org/wikipedia/commons/thumb/e/ec/Heroku_logo.svg/512px-Heroku_logo.svg.png)

# Deploy Edrys to Heroku

[Heroku](https://heroku.com) is a cloud platform as a service (PaaS) supporting
several programming languages, with support for:

* Ruby programming language
* Java
* Node.js
* Scala
* Clojure
* Python
* PHP
* Go
* and others

Web-site: https://heroku.com

## Procfile

Add a local `Procfile` to the root of the project with the following content:

```
web: deno run --allow-net=":$PORT" --allow-env -A server/app.ts --serve-path dist/static --address 0.0.0.0:$PORT
```

## Login

``` bash
$ heroku login
heroku: Press any key to open up the browser to login or q to exit: 
Opening browser to https://cli-auth.heroku.com/auth/cli/browser/xxxxx
Logging in... done
Logged in as xxxxxx@web.de
```

## Create Heroku App

``` bash
$ heroku apps:create --buildpack https://github.com/chibat/heroku-buildpack-deno.git
Creating app... done, ⬢ thawing-peak-50396
Setting buildpack to https://github.com/chibat/heroku-buildpack-deno.git... done
https://thawing-peak-50396.herokuapp.com/ | https://git.heroku.com/thawing-peak-50396.git
```

## Push via Git

``` bash
$ heroku git:remote --app thawing-peak-50396
set git remote heroku to https://git.heroku.com/thawing-peak-50396.git
```

``` bash
$ heroku git:remote --app thawing-peak-50396.git
set git remote heroku to https://git.heroku.com/thawing-peak-50396.git
```

``` bash
$ git push heroku main
Objekte aufzählen: 5, fertig.
Zähle Objekte: 100% (5/5), fertig.
Delta-Kompression verwendet bis zu 12 Threads.
Komprimiere Objekte: 100% (3/3), fertig.
Schreibe Objekte: 100% (3/3), 312 Bytes | 312.00 KiB/s, fertig.
Gesamt 3 (Delta 2), Wiederverwendet 0 (Delta 0), Pack wiederverwendet 0
remote: Compressing source files... done.
remote: Building source:
remote: 
remote: -----> Building on the Heroku-20 stack
remote: -----> Using buildpack: https://github.com/chibat/heroku-buildpack-deno.git
remote: -----> https://github.com/chibat/heroku-buildpack-deno.git app detected
remote: 
remote: ######################################################################## 100.0%
remote: Archive:  /tmp/build_82e99320/.heroku/bin/deno.zip
remote:   inflating: /tmp/build_82e99320/.heroku/bin/deno  
remote: Deno was installed successfully to /tmp/build_82e99320/.heroku/bin/deno
remote: Manually add the directory to your $HOME/.bash_profile (or similar)
remote:   export DENO_INSTALL="/tmp/build_82e99320/.heroku"
remote:   export PATH="$DENO_INSTALL/bin:$PATH"
remote: Run '/tmp/build_82e99320/.heroku/bin/deno --help' to get started
remote: Download https://deno.land/std/crypto/mod.ts
remote: Download https://deno.land/std/encoding/base64.ts
remote: Download https://deno.land/std/flags/mod.ts
...
remote: Check file:///app/server/app.ts
remote: -----> Discovering process types
remote:        Procfile declares types -> web
remote: 
remote: -----> Compressing...
remote:        Done: 39.5M
remote: -----> Launching...
remote:        Released v7
remote:        https://thawing-peak-50396.herokuapp.com/ deployed to Heroku
remote: 
remote: Verifying deploy... done.
To https://git.heroku.com/thawing-peak-50396.git
   eb6649e..543e611  main -> main
```

## Status

``` bash
$ heroku apps:info
=== thawing-peak-50396
Auto Cert Mgmt: false
Dynos:          web: 1
Git URL:        https://git.heroku.com/thawing-peak-50396.git
Owner:          andredietrich@web.de
Region:         us
Repo Size:      5 MB
Slug Size:      40 MB
Stack:          heroku-20
Web URL:        https://thawing-peak-50396.herokuapp.com/
```
