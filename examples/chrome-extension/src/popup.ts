declare const chrome: any;

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;

$("prove").addEventListener("click", async () => {
  $("out").textContent = "notarizing…";
  const reply = await chrome.runtime.sendMessage({
    type: "prove",
    url: $("url").value,
    jsonPaths: $("paths").value.split(",").map((p) => p.trim()).filter(Boolean),
  });
  $("out").textContent = JSON.stringify(reply.ok ? reply.result : reply.error, null, 2);
});
