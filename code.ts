/// <reference lib="dom" />

// Show UI with default size
figma.showUI(__html__, { width: 300, height: 400 });

// Define message types for communication between UI and plugin
interface ImageUpload {
  type: 'upload-image';
  imageData: Uint8Array;
  fileName: string;
}

interface PluginMessage {
  type: 'generate-alt-text' | 'error' | 'caption' | 'loading' | 'upload-image' | 'upload-multiple-images';
  message?: string;
  caption?: string;
  imageId?: string;
  imageData?: Uint8Array;
  images?: ImageUpload[];
}

interface ProcessImageResult {
  type: 'process-image-result';
  error?: string;
  caption?: string;
  warning?: string;
}

const REQUEST_TIMEOUT_MS = 30000;

// Environment and secrets are injected by webpack
declare const PLUGIN_SECRET: string;
declare const API_URL: string;

let sessionToken: string | null = null;

async function getSessionToken(): Promise<string> {
  if (sessionToken) return sessionToken;

  // Debug log to see what URL and secret we're using
  console.log('API_URL:', API_URL);
  console.log('PLUGIN_SECRET:', PLUGIN_SECRET ? 'Secret exists' : 'Secret is undefined');
  console.log('Authenticating with backend at:', `${API_URL}/auth`);

  try {
    // Get the current user's ID from Figma
    const userId = figma.currentUser?.id;
    if (!userId) {
      throw new Error('Could not get user ID');
    }

    // Create a hidden iframe with our proxy page
    const proxyUrl = 'https://sambabib.github.io/fig-caption-ai-proxy/';
    figma.showUI(
      `<script>window.location.href = "${proxyUrl}";</script>`,
      { visible: false, width: 1, height: 1 }
    );

    return new Promise((resolve, reject) => {
      const messageHandler = (event: { data: { pluginMessage: { type: string; token?: string; error?: string } } }) => {
        const msg = event.data.pluginMessage;
        if (msg.type === 'auth-result') {
          // Clean up the hidden iframe
          figma.closePlugin();
          
          if (msg.error) {
            reject(new Error(msg.error));
          } else if (msg.token) {
            sessionToken = msg.token;
            resolve(sessionToken);
          } else {
            reject(new Error('No token received'));
          }
        }
      };

      // Listen for response from proxy
      figma.ui.onmessage = messageHandler;

      // Send auth request to proxy
      figma.ui.postMessage({
        type: 'auth',
        apiUrl: API_URL,
        secret: PLUGIN_SECRET,
        userId: userId
      });

      // Add timeout
      setTimeout(() => {
        figma.closePlugin();
        reject(new Error('Authentication request timed out'));
      }, REQUEST_TIMEOUT_MS);
    });
  } catch (error) {
    console.error('Authentication error:', error);
    throw new Error(`Authentication error: ${error instanceof Error ? error.message : String(error)}`);
  }
}



async function processImage(imageBytes: Uint8Array, retryCount = 0): Promise<string> {
  const MAX_RETRIES = 3;

  try {
    console.log('Attempting to process image, size:', imageBytes.length, 'bytes');
    const token = await getSessionToken();
    console.log('Token obtained successfully:', token ? 'Yes' : 'No');

    // Create a hidden iframe with our proxy page
    const proxyUrl = 'https://sambabib.github.io/fig-caption-ai-proxy/';
    figma.showUI(
      `<script>window.location.href = "${proxyUrl}";</script>`,
      { visible: false, width: 1, height: 1 }
    );

    return new Promise((resolve, reject) => {
      const messageHandler = (event: { data: { pluginMessage: ProcessImageResult } }) => {
        const msg = event.data.pluginMessage;
        if (msg.type === 'process-image-result') {
          // Clean up the hidden iframe
          figma.closePlugin();
          
          if (msg.error) {
            reject(new Error(msg.error));
          } else if (msg.caption) {
            if (msg.warning) {
              figma.notify(msg.warning, { timeout: 10000 });
            }
            resolve(msg.caption);
          } else {
            reject(new Error('No caption received'));
          }
        }
      };

      // Listen for response from proxy
      figma.ui.onmessage = messageHandler;

      // Send request to proxy
      figma.ui.postMessage({
        type: 'process-image',
        imageBytes: Array.from(imageBytes),
        token: token,
        apiUrl: API_URL
      });

      // Add timeout
      setTimeout(() => {
        window.removeEventListener('message', messageHandler);
        reject(new Error('Request timed out'));
      }, REQUEST_TIMEOUT_MS);
    });
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
  // Create a text node below the image
  const textNode = figma.createText();

  // Position the text node below the image
  textNode.x = imageNode.x;
  textNode.y = imageNode.y + imageNode.height + 10; // 10px spacing
  textNode.resize(imageNode.width, textNode.height);
  textNode.textAlignHorizontal = 'LEFT';
  textNode.textAutoResize = 'HEIGHT';
  
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
      
      // Load fonts and set text content
      await figma.loadFontAsync({ family: "Inter", style: "Regular" });
      textNode.fontName = { family: "Inter", style: "Regular" };
      textNode.characters = caption;
      textNode.fontSize = 14;
      textNode.fills = [{ type: 'SOLID', color: { r: 0, g: 0, b: 0 } }];
      
      figma.currentPage.appendChild(textNode);

      figma.ui.postMessage({ type: "caption", caption });
    } catch (error) {
      figma.ui.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : "Error processing image."
      });
    }
  } else if (msg.type === "upload-multiple-images") {
    if (!msg.images || msg.images.length === 0) {
      figma.ui.postMessage({ type: "error", message: "No images received." });
      return;
    }

    if (msg.images.length > 3) {
      figma.ui.postMessage({ type: "error", message: "Maximum 3 images allowed." });
      return;
    }

    try {
      figma.ui.postMessage({ type: "loading" });

      // Process all images in parallel
      const processedGroups = await Promise.all(msg.images.map(async (imageUpload) => {
        const bytes = imageUpload.imageData;
        const caption = await processImage(bytes);

        // Create a new image in Figma
        const image = figma.createImage(bytes);
        const node = figma.createRectangle();
        const { width, height } = await image.getSizeAsync();
        node.resize(width, height);
        node.fills = [{ type: 'IMAGE', imageHash: image.hash, scaleMode: 'FILL' }];
        node.setSharedPluginData('altTextSalad', 'altText', caption);
        node.name = imageUpload.fileName || 'Uploaded Image';

        // Add to current page
        figma.currentPage.appendChild(node);
        
        // Create a text node with the caption
        const textNode = createCaptionTextNode(node, caption);
        
        // Load fonts and set text content
        await figma.loadFontAsync({ family: "Inter", style: "Regular" });
        textNode.fontName = { family: "Inter", style: "Regular" };
        textNode.characters = caption;
        textNode.fontSize = 14;
        textNode.fills = [{ type: 'SOLID', color: { r: 0, g: 0, b: 0 } }];
        
        figma.currentPage.appendChild(textNode);
        
        // Group the image and caption together for uploaded images
        const group = figma.group([node, textNode], figma.currentPage);
        group.name = `${node.name} with Caption`;
        return group;
      }));

      // Arrange the groups horizontally
      let xOffset = 0;
      processedGroups.forEach((group: FrameNode | GroupNode, index: number) => {
        if (index > 0) {
          const prevGroup = processedGroups[index - 1];
          xOffset = prevGroup.x + prevGroup.width + 20; // 20px spacing
        }
        group.x = xOffset;
      });

      // Select all groups
      figma.currentPage.selection = processedGroups;

      // Send success message back to UI
      figma.ui.postMessage({ 
        type: "caption", 
        caption: `Successfully processed ${processedGroups.length} image${processedGroups.length > 1 ? 's' : ''}`
      });
    } catch (error) {
      console.error('Error processing images:', error);
      figma.ui.postMessage({
        type: "error",
        message: error instanceof Error ? error.message : "Error processing uploaded image."
      });
    }
  }
};
