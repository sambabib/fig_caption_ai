figma.showUI(__html__, { width: 300, height: 200 });

interface PluginMessage {
  type: string;
  message?: string;
  caption?: string;
}

figma.ui.onmessage = async (msg: { type: string }) => {
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
      const errorMessage: PluginMessage = { type: "error", message: "Image hash not found." };
      figma.ui.postMessage(errorMessage);
      return;
    }

    try {
      const image = figma.getImageByHash(imageHash);
      if (!image) {
        figma.ui.postMessage({ type: "error", message: "Failed to retrieve image." });
        return;
      }

      const imageBytes = await image.getBytesAsync();

      const response = await fetch("", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image: Array.from(imageBytes) }),
      });

      const data = await response.json();

      if (data.caption) {
        figma.ui.postMessage({ type: "caption", caption: data.caption });
      } else {
        figma.ui.postMessage({ type: "error", message: "Failed to generate caption." });
      }
    } catch (error) {
      figma.ui.postMessage({ type: "error", message: "Error processing image." });
    }
  }
};
