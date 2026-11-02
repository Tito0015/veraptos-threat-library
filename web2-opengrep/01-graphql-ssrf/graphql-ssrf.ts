import axios from "axios";

const ALLOW = new Set(["api.example.com"]);

export async function badResolver(_root: unknown, args: { url: string }) {
  // ruleid: graphql-ssrf
  return fetch(args.url);
}

export async function badResolverAxios(_root: unknown, args: { endpoint: string }) {
  // ruleid: graphql-ssrf
  return axios.get(args.endpoint);
}

export async function safeResolver(_root: unknown, args: { url: string }) {
  const u = new URL(args.url);
  if (!ALLOW.has(u.host)) throw new Error("blocked");
  // ok: graphql-ssrf
  return fetch("https://api.example.com/v1/proxy");
}

export async function safeAllowlist(_root: unknown, args: { url: string }) {
  if (args.url.startsWith("https://api.example.com")) {
    // ok: graphql-ssrf
    return fetch(args.url);
  }
  throw new Error("blocked");
}
