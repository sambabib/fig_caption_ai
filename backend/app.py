from flask import Flask, request, jsonify
from transformers import BlipProcessor, BlipForConditionalGeneration
from PIL import Image
import io

app = Flask(__name__)

MODEL_NAME = "Salesforce/blip-image-captioning-base"
processor = BlipProcessor.from_pretrained(MODEL_NAME)
model = BlipForConditionalGeneration.from_pretrained(MODEL_NAME)

@app.route("/")
def home():
    return "BLIP Image Captioning API is running!"

@app.route("/generate-caption", methods=["POST"])
def generate_caption():
    try:
        if "image" not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        image = request.files["image"].read()
        image = Image.open(io.BytesIO(image)).convert("RGB")

        inputs = processor(images=image, return_tensors="pt")

        output = model.generate(**inputs)
        caption = processor.decode(output[0], skip_special_tokens=True)

        return jsonify({"caption": caption})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
