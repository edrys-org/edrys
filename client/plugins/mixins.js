import Vue from 'vue'

import { load } from 'js-yaml'

function loadResource(type, url, base) {
    if (url.match(/(https?)?:\/\//i)) {
        if (type === 'script') {
            return `<script src="${url}"></script>`
        } else {
            return `<link rel="stylesheet" href="${url}" />`
        }
    }

    const absoluteURL = (new URL(url, base)).toString()

    return `<script>
        fetch("${absoluteURL}")
        .then((response) => response.text())
        .then((code) => {
            const blob = new Blob([code], { type: "text/${type}" })
            const blobUrl = window.URL.createObjectURL(blob)

            switch("${type}") {
                case "script": {
                    const tag = document.createElement('script')
                    tag.setAttribute('src', blobUrl)
                    document.head.appendChild(tag)
                    break
                }
                case "css": {
                    const tag = document.createElement('link')
                    tag.setAttribute('rel', 'stylesheet')
                    tag.setAttribute('href', blobUrl)
                    document.head.appendChild(tag)
                    break
                }
                default: {
                    console.warn("Unknown type: ${type}")
                }
            }
        })
        .catch((e) => {
            console.warn("failed to fetch: ${absoluteURL}")
        })
    </script>
    `
}


function replace(code, baseURL) {
    try {
        let head = code.match(/<head>.*?<\/head>/is)[0]

        head = head.replace(/<script.*?src=(?:'|")([^"']+)(?:'|").*?>.*?<\/script>/igms, (pat) => {
            let url = pat.match(/src=(?:'|")([^"']+)(?:'|")/is)

            if (url) {
                url = url[1]

                if (!(url.startsWith('https://') || url.startsWith('http://'))) {
                    return loadResource('script', url, baseURL)
                }
            }

            return pat
        })

        head = head.replace(/<link.*?href=(?:'|")([^"']+)(?:'|").*?>/igms, (pat) => {
            let url = pat.match(/href=(?:'|")([^"']+)(?:'|")/is)

            if (url) {
                url = url[1]

                if (!(url.startsWith('https://') || url.startsWith('http://'))) {
                    return loadResource('css', url, baseURL)
                }
            }

            return pat
        })

        return code.replace(/<head>.*?<\/head>/is, head)
    } catch (e) {
        console.warn("problems parsing html:", e)
    }
}


Vue.mixin({
    methods: {
        async scrapeModule(module) {
            try {
                const response = await fetch(module.url)
                const content = await response.text()

                if (module.url.match(/\.ya?ml$/i)) {
                    try {

                        const yaml = load(content)
                        
                        const links = yaml.load?.links || []
                        const scripts = yaml.load?.scripts || []
                    
                        const code = `<!DOCTYPE html>
                        <html>
                        <head>
                        ${links.map((url) => { return loadResource('css', url, module.url) }).join("\n")}
                        
                            ${scripts.map((url) => { return loadResource('script', url, module.url) }).join("\n")}

                            <style type="module">${yaml.style || ''}</style>
                            <script>${ yaml.main }</script>
                            </head>
                            <body>
                            ${yaml.body || ''}
                            </body>
                            </html>
                            `
                            
                            return {
                                ...module,
                                name: yaml.name,
                                description: yaml.description,
                                icon: yaml.icon || 'mdi-package',
                                shownIn: yaml['show-in'] || ['*'],
                                srcdoc: "data:text/html," + escape(code),
                                origin: '*'
                            }
                        } catch (error) {
                            console.warn("loading yaml:", error)

                            throw new Error('Could not load the YAML-declaration: '+ error.message);
                        }
                    } else {
                    const moduleEl = document.createElement('html')
                    moduleEl.innerHTML = content
                    const meta = Object.fromEntries(Object.values(moduleEl.getElementsByTagName('meta')).map(m => ([m.name, m.content])))

                    if (meta['fetch'] && meta['fetch'] !== 'false') {
                        return {
                            ...module,
                            name: moduleEl.getElementsByTagName("title")[0].innerText || meta['name'],
                            description: meta['description'],
                            icon: meta['icon'] || 'mdi-package',
                            shownIn: (meta['show-in'] || '*').replaceAll(' ', '').split(','), // or 'station'
                            srcdoc: "data:text/html," + escape(replace(content, module.url)),
                            origin: '*'
                        }
                    }

                    try {
                        return {
                            ...module,
                            name: moduleEl.getElementsByTagName("title")[0].innerText || meta['name'],
                            description: meta['description'],
                            icon: meta['icon'] || 'mdi-package',
                            shownIn: (meta['show-in'] || '*').replaceAll(' ', '').split(',') // or 'station'
                        }
                    } catch (error) {
                        throw new Error('This does not seem to be a valid module declaration, check the URL manually.');
                    }
                }
            } catch (error) {
                return {
                    ...module,
                    name: '<Error: exception scraping module>',
                    description: error,
                    icon: 'mdi-alert',
                    shownIn: ''
                }
            }

        },
        download(filename, text) {
            /**
             * https://stackoverflow.com/questions/3665115/how-to-create-a-file-in-memory-for-user-to-download-but-not-through-server
             */
            const element = document.createElement('a');
            element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
            element.setAttribute('download', filename);

            element.style.display = 'none';
            document.body.appendChild(element);

            element.click();

            document.body.removeChild(element);
        },
        uuidv4() {
            /**
             * https://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid
             */
            return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
                (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
            );
        },
        debounce(func, wait, immediate) {
            /**
             * https://davidwalsh.name/javascript-debounce-function
             */
            let timeout;
            return function () {
                const context = this, args = arguments;
                const later = function () {
                    timeout = null;
                    if (!immediate) func.apply(context, args);
                };
                const callNow = immediate && !timeout;
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
                if (callNow) func.apply(context, args);
            }
        },
        setToValue(obj, pathArr, value) {
            let i = 0;

            for (i = 0; i < pathArr.length - 1; i++) {
                obj = obj[pathArr[i]];
                if (!obj[pathArr[i + 1]])
                    obj[pathArr[i + 1]] = {}
            }
            obj[pathArr[i]] = value;
            // if (value == undefined)
            //     delete obj[pathArr[i]]
        }

    }
})