/* One request policy for ordinary, multipart, and streamed API requests. */
window.m3mxFetch = async function (input, options = {}) {
  const url = new URL(typeof input === "string" ? input : input.url, location.href);
  if (url.origin !== location.origin) throw new Error("Cross-origin requests are disabled");
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-M3MX-Token", document.querySelector('meta[name="m3mx-token"]').content);
  }
  return fetch(input, { ...options, headers, credentials: "same-origin", redirect: "error" });
};
