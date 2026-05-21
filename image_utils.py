#!/usr/bin/env python3
"""
Classic Image Manipulation Utilities

Pillow-based utilities for deterministic pixel-level operations.
Use for resize, crop, composite, format conversion, watermarks, and more.

Usage:
    from image_utils import ImageUtils

    image = ImageUtils.load("path/to/image.png")
    resized = ImageUtils.resize(image, width=800, height=600)
    ImageUtils.save(resized, "output.webp", quality=90)
"""

import io
import base64
import requests
from pathlib import Path
from typing import Union, Optional, Tuple, Dict, Any

from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageEnhance


class ImageUtils:
    """Classic image manipulation utilities using Pillow/PIL."""

    # ==================== Loading & Saving ====================

    @staticmethod
    def load(source: Union[str, bytes, Path]) -> Image.Image:
        """Load image from URL, file path, bytes, or base64 string."""
        if isinstance(source, bytes):
            return Image.open(io.BytesIO(source))
        if isinstance(source, Path):
            return Image.open(source)
        if isinstance(source, str):
            if source.startswith("data:image"):
                base64_data = source.split(",", 1)[1]
                image_bytes = base64.b64decode(base64_data)
                return Image.open(io.BytesIO(image_bytes))
            if len(source) > 200 and not source.startswith(("http://", "https://", "/")):
                try:
                    image_bytes = base64.b64decode(source)
                    return Image.open(io.BytesIO(image_bytes))
                except Exception:
                    pass
            if source.startswith(("http://", "https://")):
                return ImageUtils.load_from_url(source)
            return Image.open(source)
        raise ValueError(f"Unsupported source type: {type(source)}")

    @staticmethod
    def load_from_url(url: str, timeout: int = 30) -> Image.Image:
        """Download and load image from URL."""
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "ImageUtils/1.0"})
        response.raise_for_status()
        return Image.open(io.BytesIO(response.content))

    @staticmethod
    def save(image: Image.Image, path: Union[str, Path], quality: int = 95, optimize: bool = True) -> None:
        """Save image to file with format auto-detection from extension."""
        path = Path(path)
        ext = path.suffix.lower()
        path.parent.mkdir(parents=True, exist_ok=True)
        save_image = image
        if ext in (".jpg", ".jpeg"):
            if image.mode in ("RGBA", "LA", "P"):
                save_image = image.convert("RGB")
        save_kwargs = {"optimize": optimize}
        if ext in (".jpg", ".jpeg", ".webp"):
            save_kwargs["quality"] = quality
        save_image.save(path, **save_kwargs)

    @staticmethod
    def to_bytes(image: Image.Image, format: str = "PNG", quality: int = 95) -> bytes:
        """Convert image to bytes."""
        buffer = io.BytesIO()
        save_image = image
        if format.upper() == "JPEG" and image.mode in ("RGBA", "LA", "P"):
            save_image = image.convert("RGB")
        save_kwargs = {}
        if format.upper() in ("JPEG", "WEBP"):
            save_kwargs["quality"] = quality
        save_image.save(buffer, format=format, **save_kwargs)
        return buffer.getvalue()

    @staticmethod
    def to_base64(image: Image.Image, format: str = "PNG", quality: int = 95, include_data_url: bool = False) -> str:
        """Convert image to base64 string."""
        image_bytes = ImageUtils.to_bytes(image, format, quality)
        b64_string = base64.b64encode(image_bytes).decode("utf-8")
        if include_data_url:
            mime_types = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
            mime = mime_types.get(format.upper(), "image/png")
            return f"data:{mime};base64,{b64_string}"
        return b64_string

    # ==================== Resizing & Scaling ====================

    @staticmethod
    def resize(image: Image.Image, width: Optional[int] = None, height: Optional[int] = None,
               maintain_aspect: bool = False, resample: int = Image.Resampling.LANCZOS) -> Image.Image:
        """Resize image to exact dimensions."""
        if width is None and height is None:
            raise ValueError("Must specify width, height, or both")
        orig_width, orig_height = image.size
        if width is None:
            width = int(orig_width * height / orig_height)
        elif height is None:
            height = int(orig_height * width / orig_width)
        if maintain_aspect:
            ratio = min(width / orig_width, height / orig_height)
            width = int(orig_width * ratio)
            height = int(orig_height * ratio)
        return image.resize((width, height), resample=resample)

    @staticmethod
    def scale(image: Image.Image, factor: float, resample: int = Image.Resampling.LANCZOS) -> Image.Image:
        """Scale image by factor (0.5 = half, 2.0 = double)."""
        width, height = image.size
        return image.resize((int(width * factor), int(height * factor)), resample=resample)

    @staticmethod
    def thumbnail(image: Image.Image, size: Tuple[int, int], resample: int = Image.Resampling.LANCZOS) -> Image.Image:
        """Create thumbnail that fits within size, maintaining aspect ratio."""
        result = image.copy()
        result.thumbnail(size, resample=resample)
        return result

    # ==================== Cropping ====================

    @staticmethod
    def crop(image: Image.Image, left: int, top: int, right: int, bottom: int) -> Image.Image:
        """Crop image to region."""
        return image.crop((left, top, right, bottom))

    @staticmethod
    def crop_center(image: Image.Image, width: int, height: int) -> Image.Image:
        """Crop from center of image."""
        img_width, img_height = image.size
        left = (img_width - width) // 2
        top = (img_height - height) // 2
        return image.crop((left, top, left + width, top + height))

    @staticmethod
    def crop_to_aspect(image: Image.Image, ratio: Union[str, float], anchor: str = "center") -> Image.Image:
        """Crop image to target aspect ratio."""
        if isinstance(ratio, str):
            w, h = map(int, ratio.split(":"))
            target_ratio = w / h
        else:
            target_ratio = ratio
        img_width, img_height = image.size
        current_ratio = img_width / img_height
        if current_ratio > target_ratio:
            new_width = int(img_height * target_ratio)
            new_height = img_height
        else:
            new_width = img_width
            new_height = int(img_width / target_ratio)
        if anchor == "center":
            left = (img_width - new_width) // 2
            top = (img_height - new_height) // 2
        elif anchor == "top":
            left = (img_width - new_width) // 2
            top = 0
        elif anchor == "bottom":
            left = (img_width - new_width) // 2
            top = img_height - new_height
        elif anchor == "left":
            left = 0
            top = (img_height - new_height) // 2
        elif anchor == "right":
            left = img_width - new_width
            top = (img_height - new_height) // 2
        else:
            raise ValueError(f"Unknown anchor: {anchor}")
        return image.crop((left, top, left + new_width, top + new_height))

    # ==================== Compositing ====================

    @staticmethod
    def paste(background: Image.Image, foreground: Image.Image, position: Tuple[int, int] = (0, 0),
              use_alpha: bool = True) -> Image.Image:
        """Paste foreground onto background at position."""
        result = background.copy()
        if result.mode != "RGBA":
            result = result.convert("RGBA")
        if use_alpha and foreground.mode == "RGBA":
            result.paste(foreground, position, foreground)
        else:
            result.paste(foreground, position)
        return result

    @staticmethod
    def composite(background: Image.Image, foreground: Image.Image, mask: Optional[Image.Image] = None) -> Image.Image:
        """Alpha composite foreground over background."""
        bg = background.convert("RGBA") if background.mode != "RGBA" else background
        fg = foreground.convert("RGBA") if foreground.mode != "RGBA" else foreground
        if mask:
            mask = mask.convert("L")
            return Image.composite(fg, bg, mask)
        return Image.alpha_composite(bg, fg)

    @staticmethod
    def fit_to_canvas(image: Image.Image, width: int, height: int,
                      background_color: Tuple[int, int, int, int] = (255, 255, 255, 0),
                      position: str = "center") -> Image.Image:
        """Fit image onto canvas, letterboxing if needed."""
        resized = ImageUtils.resize(image, width, height, maintain_aspect=True)
        canvas = Image.new("RGBA", (width, height), background_color)
        res_width, res_height = resized.size
        if position == "center":
            x = (width - res_width) // 2
            y = (height - res_height) // 2
        elif position == "top":
            x = (width - res_width) // 2
            y = 0
        elif position == "bottom":
            x = (width - res_width) // 2
            y = height - res_height
        else:
            x = (width - res_width) // 2
            y = (height - res_height) // 2
        canvas.paste(resized, (x, y), resized if resized.mode == "RGBA" else None)
        return canvas

    # ==================== Borders & Padding ====================

    @staticmethod
    def add_border(image: Image.Image, width: int, color: Tuple[int, int, int] = (0, 0, 0)) -> Image.Image:
        """Add solid border around image."""
        img_width, img_height = image.size
        result = Image.new(image.mode, (img_width + 2 * width, img_height + 2 * width), color)
        result.paste(image, (width, width))
        return result

    @staticmethod
    def add_padding(image: Image.Image, padding: Union[int, Tuple[int, int, int, int]],
                    color: Tuple[int, int, int, int] = (255, 255, 255, 255)) -> Image.Image:
        """Add whitespace padding around image."""
        if isinstance(padding, int):
            left = top = right = bottom = padding
        else:
            left, top, right, bottom = padding
        img_width, img_height = image.size
        result = Image.new("RGBA", (img_width + left + right, img_height + top + bottom), color)
        if image.mode == "RGBA":
            result.paste(image, (left, top), image)
        else:
            result.paste(image, (left, top))
        return result

    # ==================== Transforms ====================

    @staticmethod
    def rotate(image: Image.Image, angle: float, expand: bool = True,
               fill_color: Tuple[int, int, int, int] = (255, 255, 255, 0)) -> Image.Image:
        """Rotate image by degrees (counter-clockwise)."""
        return image.rotate(angle, expand=expand, fillcolor=fill_color, resample=Image.Resampling.BICUBIC)

    @staticmethod
    def flip_horizontal(image: Image.Image) -> Image.Image:
        """Mirror image horizontally."""
        return image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)

    @staticmethod
    def flip_vertical(image: Image.Image) -> Image.Image:
        """Flip image vertically."""
        return image.transpose(Image.Transpose.FLIP_TOP_BOTTOM)

    # ==================== Watermarks ====================

    @staticmethod
    def add_text_watermark(image: Image.Image, text: str, position: str = "bottom-right",
                           font_size: int = 24, color: Tuple[int, int, int, int] = (255, 255, 255, 128),
                           margin: int = 10) -> Image.Image:
        """Add text watermark to image."""
        result = image.convert("RGBA")
        overlay = Image.new("RGBA", result.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except (IOError, OSError):
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        img_width, img_height = result.size
        positions = {
            "bottom-right": (img_width - text_width - margin, img_height - text_height - margin),
            "bottom-left": (margin, img_height - text_height - margin),
            "top-right": (img_width - text_width - margin, margin),
            "top-left": (margin, margin),
            "center": ((img_width - text_width) // 2, (img_height - text_height) // 2),
        }
        x, y = positions.get(position, positions["bottom-right"])
        draw.text((x, y), text, font=font, fill=color)
        return Image.alpha_composite(result, overlay)

    @staticmethod
    def add_image_watermark(image: Image.Image, watermark: Image.Image, position: str = "bottom-right",
                            opacity: float = 0.5, scale: float = 0.2, margin: int = 10) -> Image.Image:
        """Add image/logo watermark."""
        result = image.convert("RGBA")
        wm_width = int(result.width * scale)
        wm = ImageUtils.resize(watermark, width=wm_width)
        if wm.mode == "RGBA":
            r, g, b, a = wm.split()
            a = a.point(lambda x: int(x * opacity))
            wm = Image.merge("RGBA", (r, g, b, a))
        else:
            wm = wm.convert("RGBA")
        img_width, img_height = result.size
        wm_w, wm_h = wm.size
        positions = {
            "bottom-right": (img_width - wm_w - margin, img_height - wm_h - margin),
            "bottom-left": (margin, img_height - wm_h - margin),
            "top-right": (img_width - wm_w - margin, margin),
            "top-left": (margin, margin),
            "center": ((img_width - wm_w) // 2, (img_height - wm_h) // 2),
        }
        x, y = positions.get(position, positions["bottom-right"])
        result.paste(wm, (x, y), wm)
        return result

    # ==================== Adjustments ====================

    @staticmethod
    def adjust_brightness(image: Image.Image, factor: float) -> Image.Image:
        """Adjust brightness (1.0 = original, <1 darker, >1 lighter)."""
        return ImageEnhance.Brightness(image).enhance(factor)

    @staticmethod
    def adjust_contrast(image: Image.Image, factor: float) -> Image.Image:
        """Adjust contrast (1.0 = original)."""
        return ImageEnhance.Contrast(image).enhance(factor)

    @staticmethod
    def adjust_saturation(image: Image.Image, factor: float) -> Image.Image:
        """Adjust saturation (0 = grayscale, 1.0 = original, >1 vivid)."""
        return ImageEnhance.Color(image).enhance(factor)

    @staticmethod
    def adjust_sharpness(image: Image.Image, factor: float) -> Image.Image:
        """Adjust sharpness (1.0 = original, >1 sharper)."""
        return ImageEnhance.Sharpness(image).enhance(factor)

    @staticmethod
    def blur(image: Image.Image, radius: float = 2.0) -> Image.Image:
        """Apply Gaussian blur."""
        return image.filter(ImageFilter.GaussianBlur(radius=radius))

    # ==================== Web Optimization ====================

    @staticmethod
    def optimize_for_web(image: Image.Image, max_dimension: int = 1920, format: str = "WEBP",
                         quality: int = 85) -> bytes:
        """Optimize image for web delivery."""
        width, height = image.size
        if width > max_dimension or height > max_dimension:
            image = ImageUtils.resize(image, max_dimension, max_dimension, maintain_aspect=True)
        return ImageUtils.to_bytes(image, format, quality)

    # ==================== Info ====================

    @staticmethod
    def get_info(image: Image.Image) -> Dict[str, Any]:
        """Get image metadata (width, height, mode, format, etc.)."""
        return {
            "width": image.width,
            "height": image.height,
            "mode": image.mode,
            "format": image.format,
            "has_alpha": image.mode in ("RGBA", "LA", "PA"),
            "aspect_ratio": round(image.width / image.height, 3),
        }
