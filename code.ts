/// <reference lib="dom" />

// Show UI with default size
figma.showUI(__html__, { width: 300, height: 400 });

// Define message types for communication between UI and plugin
interface PluginMessage {
  type: 'generate-alt-text' | 'error' | 'caption' | 'loading' | 'upload-image';
  message?: string;
  caption?: string;
  imageId?: string;
  imageData?: number[];
}

// Environment and secrets are injected by webpack
declare const PLUGIN_SECRET: string;
declare const API_URL: string;

let sessionToken: string | null = null;

async function getSessionToken(): Promise<string> {
  if (sessionToken) return sessionToken;

  const response = await fetch(`${API_URL}/auth`, {
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

  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Request timeout')), TIMEOUT);
  });

  const fetchPromise = (async () => {
    // Get session token before making request
    const token = await getSessionToken();

    const response: Response = await fetch(resource, {
      ...options,
      headers: {
        ...options.headers,
        'X-Session-Token': token
      }
    });

    // If session expired, retry once with new token
    if (response.status === 401) {
      sessionToken = null; // Clear expired token
      const newToken = await getSessionToken();
      return fetch(resource, {
        ...options,
        headers: {
          ...options.headers,
          'X-Session-Token': newToken
        }
      });
    }

    return response;
  })();

  return Promise.race([fetchPromise, timeoutPromise]);
}

async function processImage(imageBytes: Uint8Array, retryCount = 0): Promise<string> {
  const MAX_RETRIES = 3;

  try {
    const token = await getSessionToken();
    const response = await fetchWithTimeout(`${API_URL}/generate-caption`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Authorization': `Bearer ${token}`
      },
      body: imageBytes
    }) as Response;

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json() as { caption?: string };
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

// Handle command invocations
figma.on('run', ({ command }) => {
  if (command === 'generateCaption') {
    generateCaptionForSelection();
  }
});

// Create a text node with the caption below the image
function createCaptionTextNode(imageNode: RectangleNode, caption: string): TextNode {
  // Load a font first
  const textNode = figma.createText();
  
  // Position below the image
  textNode.x = imageNode.x;
  textNode.y = imageNode.y + imageNode.height + 16; // 16px spacing
  textNode.resize(imageNode.width, textNode.height);
  textNode.textAlignHorizontal = 'LEFT';
  
  // Set the text content once fonts are loaded
  const loadFontAndSetText = async () => {
    await figma.loadFontAsync({ family: "Inter", style: "Regular" });
    textNode.characters = caption;
    textNode.fontSize = 14;
    textNode.fills = [{ type: 'SOLID', color: { r: 0, g: 0, b: 0 } }];
    
    // Add a label to identify this as a caption
    textNode.name = `Caption for ${imageNode.name || 'Image'}`;
  };
  
  loadFontAndSetText();
  return textNode;
}

// Process selected image and generate caption
async function generateCaptionForSelection() {
  const selection = figma.currentPage.selection;
  if (selection.length === 0 || selection[0].type !== "RECTANGLE") {
    figma.notify("Please select an image rectangle");
    return;
  }

  const selectedNode = selection[0] as RectangleNode;
  const fills = selectedNode.fills as ReadonlyArray<Paint>;

  if (!fills.length || fills[0].type !== "IMAGE") {
    figma.notify("Selected object is not an image");
    return;
  }

  const imageFill = fills[0] as ImagePaint;
  const imageHash = imageFill.imageHash;

  if (!imageHash) {
    figma.notify("Image hash not found");
    return;
  }

  try {
    figma.notify("Generating caption...", { timeout: 60000 });

    const image = figma.getImageByHash(imageHash);
    if (!image) {
      throw new Error("Failed to retrieve image");
    }

    const imageBytes = await image.getBytesAsync();
    const caption = await processImage(imageBytes);

    // Set the description in Figma
    selectedNode.setSharedPluginData('altTextSalad', 'altText', caption);
    
    // Create a text node with the caption
    const textNode = createCaptionTextNode(selectedNode, caption);
    figma.currentPage.appendChild(textNode);
    
    // Group the image and caption together
    const nodes = [selectedNode, textNode];
    const group = figma.group(nodes, figma.currentPage);
    group.name = 'Image with Caption';
    
    // Select the group
    figma.currentPage.selection = [group];
    
    // Show success notification with the caption
    figma.notify(`Caption generated: ${caption}`);
  } catch (error) {
    figma.notify(error instanceof Error ? error.message : "Error processing image");
  }
}

// Handle messages from the UI
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
      
      // Create a text node with the caption
      const textNode = createCaptionTextNode(selectedNode, caption);
      figma.currentPage.appendChild(textNode);
      
      // Group the image and caption together
      const nodes = [selectedNode, textNode];
      const group = figma.group(nodes, figma.currentPage);
      group.name = 'Image with Caption';

      figma.ui.postMessage({ type: "caption", caption });
    } catch (error) {
      figma.ui.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : "Error processing image."
      });
    }
  } else if (msg.type === "upload-image") {
    if (!msg.imageData) {
      figma.ui.postMessage({ type: "error", message: "No image data received." });
      return;
    }

    try {
      figma.ui.postMessage({ type: "loading" });

      // Convert number array to Uint8Array
      const bytes = Uint8Array.from(msg.imageData as number[]);

      // Process the image
      const caption = await processImage(bytes);

      // Create a new image in Figma
      const image = figma.createImage(bytes);
      const node = figma.createRectangle();
      const { width, height } = await image.getSizeAsync();
      node.resize(width, height);
      node.fills = [{ type: 'IMAGE', imageHash: image.hash, scaleMode: 'FILL' }];
      node.setSharedPluginData('altTextSalad', 'altText', caption);
      node.name = 'Uploaded Image';

      // Add to current page
      figma.currentPage.appendChild(node);
      
      // Create a text node with the caption
      const textNode = createCaptionTextNode(node, caption);
      figma.currentPage.appendChild(textNode);
      
      // Group the image and caption together
      const nodes = [node, textNode];
      const group = figma.group(nodes, figma.currentPage);
      group.name = 'Uploaded Image with Caption';
      
      // Select the group
      figma.currentPage.selection = [group];

      // Send caption back to UI
      figma.ui.postMessage({ type: "caption", caption });
    } catch (error) {
      figma.ui.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : "Error processing uploaded image."
      });
    }
  }
};
