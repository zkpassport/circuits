// Serves target/packaged over plain HTTP with the URL layout the registry client expects, so a
// phone on the same Wi-Fi can pull locally packaged circuits:
//   /by-version/<version>/manifest.json and /by-root/<root>/manifest.json -> manifest.json
//   /by-hash/<vkey hash>.json                                             -> circuits/<name>.json
// Usage: npm run serve-circuits [-- --port 8000]
import { createServer } from "node:http"
import { networkInterfaces } from "node:os"
import { readFile } from "node:fs/promises"
import path from "node:path"

const PACKAGED_DIR = path.resolve("target/packaged")
const portArg = process.argv.indexOf("--port")
const PORT = portArg > -1 ? Number(process.argv[portArg + 1]) : 8000

const normaliseHash = (hash) => hash.toLowerCase().replace(/^0x/, "").replace(/^0+/, "")

async function readManifest() {
  return JSON.parse(await readFile(path.join(PACKAGED_DIR, "manifest.json"), "utf8"))
}

async function resolve(url) {
  const { pathname } = new URL(url, "http://localhost")
  if (
    pathname === "/manifest.json" ||
    /^\/by-(version|root)\/[^/]+\/manifest\.json$/.test(pathname)
  ) {
    return path.join(PACKAGED_DIR, "manifest.json")
  }
  const byHash = pathname.match(/^\/by-hash\/([0-9a-fA-Fx]+)\.json$/)
  if (byHash) {
    const wanted = normaliseHash(byHash[1])
    const { circuits } = await readManifest()
    const name = Object.keys(circuits).find((n) => normaliseHash(circuits[n].hash) === wanted)
    return name ? path.join(PACKAGED_DIR, "circuits", `${name}.json`) : null
  }
  const byName = pathname.match(/^\/circuits\/([\w-]+)\.json$/)
  return byName ? path.join(PACKAGED_DIR, "circuits", `${byName[1]}.json`) : null
}

createServer(async (req, res) => {
  try {
    const file = await resolve(req.url ?? "/")
    if (!file) {
      res.writeHead(404).end("not found")
      console.log(`404 ${req.url}`)
      return
    }
    const body = await readFile(file)
    res.writeHead(200, {
      "content-type": "application/json",
      "content-length": body.length,
      // The verify popup fetches from a browser on another origin
      "access-control-allow-origin": "*",
    })
    res.end(body)
    console.log(`200 ${req.url} -> ${path.relative(PACKAGED_DIR, file)} (${body.length} bytes)`)
  } catch (error) {
    res.writeHead(500).end(String(error))
    console.log(`500 ${req.url}: ${error}`)
  }
}).listen(PORT, "0.0.0.0", () => {
  const ips = Object.values(networkInterfaces())
    .flat()
    .filter((i) => i && i.family === "IPv4" && !i.internal)
    .map((i) => i.address)
  console.log(`Serving ${PACKAGED_DIR} on port ${PORT}`)
  for (const ip of ips) console.log(`  http://${ip}:${PORT}/manifest.json`)
})
