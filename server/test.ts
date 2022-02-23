import puppeteer from "https://deno.land/x/puppeteer@9.0.2/mod.ts";
import { parse } from "https://deno.land/std/flags/mod.ts"

/**
 * E2E testing done in puppeteer (WIP)
 */

const args = parse(Deno.args)

const browser = await puppeteer.launch({ 
  headless: args['headless'] === undefined, 
  slowMo: Number(args['slowMo'] || 0)
});

const adminPage = await browser.newPage()

const ctx1 = await browser.createIncognitoBrowserContext()
const ctx2 = await browser.createIncognitoBrowserContext()

const page1 = await ctx1.newPage();
await page1.goto(args['host'] || 'http://localhost:8000');
await page1.screenshot({ path: "example1.png" });

const page2 = await ctx2.newPage();
await page2.goto(args['host'] || 'http://localhost:8000');
await page2.screenshot({ path: "example2.png" });

await browser.close();