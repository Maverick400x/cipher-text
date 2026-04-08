from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

app = FastAPI()

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Request model
class TextRequest(BaseModel):
    text: str
    shift: int

# ✅ Cipher logic
def caesar_cipher_steps(text, shift):
    steps = []
    result = ""

    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shifted = chr((ord(char) - base + shift) % 26 + base)

            steps.append({
                "original": char,
                "shifted": shifted
            })

            result += shifted
        else:
            steps.append({
                "original": char,
                "shifted": char
            })
            result += char

    return steps, result

# ✅ API endpoint
@app.post("/encrypt")
def encrypt(req: TextRequest):
    steps, result = caesar_cipher_steps(req.text, req.shift)

    return {
        "input": req.text,
        "key": req.shift,
        "steps": steps,
        "output": result
    }

# ✅ Serve HTML file
@app.get("/", response_class=HTMLResponse)
def serve_html():
    with open("index.html", "r") as f:
        return f.read()