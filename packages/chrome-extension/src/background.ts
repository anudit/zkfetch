import { tokenExpired, tokenUserId, type Auth } from "./auth";
import { DUOLINGO } from "./defaults";
import type { BackgroundReply, BackgroundRequest } from "./messages";

const TAB_URLS = ["https://*.duolingo.com/*"];

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(console.error);

async function saveAuth(auth?: Auth) {
  // Session storage survives service-worker suspension, but clears on browser
  // restart and is unavailable to content scripts by default.
  if (auth && !tokenExpired(auth.token)) await chrome.storage.session.set({ auth });
  else await chrome.storage.session.remove("auth");
}

async function readAuth(): Promise<Auth | undefined> {
  const cookie = await chrome.cookies.get({ url: DUOLINGO, name: "jwt_token" });
  if (cookie?.value) {
    const token = cookie.value.trim();
    const auth: Auth = { token, source: "cookie", userId: tokenUserId(token) };
    await saveAuth(auth);
    return token && !tokenExpired(token) ? auth : undefined;
  }
  const { auth } = await chrome.storage.session.get("auth") as { auth?: Auth };
  if (!auth) return undefined;
  if (auth.source === "cookie" || tokenExpired(auth.token)) {
    await saveAuth();
    return undefined;
  }
  return auth;
}

chrome.cookies.onChanged.addListener(({ cookie, removed }) => {
  if (cookie.name !== "jwt_token" || !/(^|\.)duolingo\.com$/.test(cookie.domain)) return;
  // Replacement notifications remove the old value before adding the new one.
  void saveAuth(removed ? undefined : {
    token: cookie.value.trim(), source: "cookie", userId: tokenUserId(cookie.value),
  }).catch(console.error);
});

chrome.webRequest.onBeforeSendHeaders.addListener((details): undefined => {
  // Only observe the user's Duolingo tabs, not our own extension requests.
  if (details.tabId < 0) return;
  const authorization = details.requestHeaders?.find(header => header.name.toLowerCase() === "authorization")?.value;
  const token = /^Bearer\s+(.+)$/i.exec(authorization ?? "")?.[1]?.trim();
  if (!token) return;
  const userId = tokenUserId(token) ?? /\/2017-06-30\/users\/(\d+)(?:[/?]|$)/.exec(details.url)?.[1];
  void saveAuth({ token, source: "bearer", userId }).catch(console.error);
}, { urls: TAB_URLS }, ["requestHeaders", "extraHeaders"]);

const ICON_SIZES = [16, 32, 48, 128] as const;

/** Swap the toolbar icon to contrast the OS theme; the icon has no background. */
async function applyThemeIcon(theme: "dark" | "light"): Promise<void> {
  const variant = theme === "dark" ? "light" : "dark";
  const path = Object.fromEntries(ICON_SIZES.map(size => [size, `icons/icon-${variant}${size}.png`]));
  await chrome.action.setIcon({ path });
}

async function handle(message: BackgroundRequest): Promise<BackgroundReply> {
  let tabs = await chrome.tabs.query({ url: TAB_URLS });
  if (message.type === "open-duolingo") {
    if (tabs[0]?.id !== undefined) {
      if (message.focus) {
        await chrome.tabs.update(tabs[0].id, { active: true });
        await chrome.windows.update(tabs[0].windowId, { focused: true });
      }
    } else {
      tabs = [await chrome.tabs.create({ url: `${DUOLINGO}/learn` })];
    }
  }
  const auth = await readAuth();
  return {
    ok: true,
    status: { tabOpen: tabs.length > 0, hasToken: Boolean(auth), source: auth?.source },
    ...(message.type === "auth" ? { auth } : {}),
  };
}

chrome.runtime.onMessage.addListener((message: BackgroundRequest, sender, reply: (value: BackgroundReply) => void) => {
  // Only the extension panel may request the credential. No content script or
  // external page receives tokens or controls tabs through this handler.
  const panelPath = chrome.runtime.getManifest().side_panel?.default_path;
  if (!panelPath || sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL(panelPath)) return false;
  if (message?.type === "theme") {
    // The toolbar icon has no background, so the panel reports the OS theme
    // and the icon swaps to a contrasting mark. Fire-and-forget: no reply.
    if (message.theme === "dark" || message.theme === "light") {
      void applyThemeIcon(message.theme).catch(console.error);
    }
    return false;
  }
  if (!["status", "auth", "open-duolingo"].includes(message?.type)) return false;
  handle(message).then(reply, () => reply({ ok: false, error: "Could not read the Duolingo session. Reopen the panel and try again." }));
  return true;
});
