/// <reference lib="dom" />

figma.showUI(__html__, { width: 300, height: 400 });

interface PluginMessage {
  type: 'generate-alt-text' | 'error' | 'caption' | 'loading';
  message?: string;
  caption?: string;
  imageId?: string;
}

// Environment and secrets are injected by webpack
declare const PLUGIN_SECRET: string;
declare const API_URL: string;

// Use injected API_URL
const API_BASE = API_URL;

let sessionToken: string | null = null;

async function getSessionToken(): Promise<string> {
  if (sessionToken) return sessionToken;

  const response = await fetch(`${API_BASE}/auth`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ secret: PLUGIN_SECRET })
  });

  if (!response.ok) {
    throw new Error('Failed to authenticate with backend');
  }

  const data = await response.json();
  if (!data.token) {
    throw new Error('No token received from server');
  }
  sessionToken = data.token;
  return sessionToken as string;
}

async function fetchWithTimeout(resource: string, options: RequestInit = {}) {
  const TIMEOUT = 30000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);

  try {
    // Get session token before making request
    const token = await getSessionToken();

    const response = await fetch(resource, {
      ...options,
      headers: {
        ...options.headers,
        'X-Session-Token': token
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // If session expired, retry once with new token
    if (response.status === 401) {
      sessionToken = null; // Clear expired token
      const newToken = await getSessionToken();
      const retryResponse = await fetch(resource, {
        ...options,
        headers: {
          ...options.headers,
          'X-Session-Token': newToken
        }
      });
      return retryResponse;
    }

    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

async function processImage(imageBytes: Uint8Array, retryCount = 0): Promise<string> {
  const MAX_RETRIES = 3;

  try {
    const formData = new FormData();
    const blob = new Blob([imageBytes], { type: 'image/png' });
    formData.append('image', blob);

    const response = await fetchWithTimeout(`${API_BASE}/generate-caption`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    if (!data.caption) {
      throw new Error('No caption in response');
    }

    return data.caption;
  } catch (error) {
    if (retryCount < MAX_RETRIES) {
      await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
      return processImage(imageBytes, retryCount + 1);
    }
    throw error;
  }
}

figma.ui.onmessage = async (msg: PluginMessage) => {
  if (msg.type === "generate-alt-text") {
    const selection = figma.currentPage.selection;
    if (selection.length === 0 || selection[0].type !== "RECTANGLE") {
      figma.ui.postMessage({ type: "error", message: "Please select an image." });
      return;
    }

    const selectedNode = selection[0] as RectangleNode;
    const fills = selectedNode.fills as ReadonlyArray<Paint>;

    if (!fills.length || fills[0].type !== "IMAGE") {
      figma.ui.postMessage({ type: "error", message: "Selected object is not an image." });
      return;
    }

    const imageFill = fills[0] as ImagePaint;
    const imageHash = imageFill.imageHash;

    if (!imageHash) {
      figma.ui.postMessage({ type: "error", message: "Image hash not found." });
      return;
    }

    try {
      figma.ui.postMessage({ type: "loading" });

      const image = figma.getImageByHash(imageHash);
      if (!image) {
        throw new Error("Failed to retrieve image");
      }

      const imageBytes = await image.getBytesAsync();
      const caption = await processImage(imageBytes);

      // Set the description in Figma
      selectedNode.setSharedPluginData('altTextSalad', 'altText', caption);

      figma.ui.postMessage({ type: "caption", caption });
    } catch (error) {
      figma.ui.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : "Error processing image."
      });
    }
  }
};
