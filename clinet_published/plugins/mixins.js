import Vue from 'vue'

Vue.mixin({
    methods: {
        async scrapeModule(module) {

            try {
                const moduleEl = document.createElement('html')
                moduleEl.innerHTML = (await (await fetch(module.url)).text())
                const meta = Object.fromEntries(Object.values(moduleEl.getElementsByTagName('meta')).map(m => ([m.name, m.content])))

                return {
                    ...module,
                    name: moduleEl.getElementsByTagName("title")[0].innerText || meta['name'],
                    description: meta['description'],
                    icon: meta['icon'] || 'mdi-package',
                    shownIn: (meta['show-in'] || '*').replaceAll(' ', '').split(',') // or 'station'
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