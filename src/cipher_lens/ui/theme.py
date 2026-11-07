"""Theme configuration and visual design system for Cipher-Lens.

Purely visual styling: palette, responsive hero banner, sentinel rail,
and Streamlit component restyling without logic alterations.
"""

from __future__ import annotations

import base64
import functools
import html
from pathlib import Path

import streamlit as st

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


@functools.lru_cache(maxsize=8)
def _load_asset_base64(filename: str) -> str:
    asset_file = _ASSETS_DIR / filename
    if not asset_file.exists():
        return ""
    encoded = base64.b64encode(asset_file.read_bytes()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


CL_THEME_CSS = """<style>
/* Global Cipher-Lens Dark Theme */
:root {
    --cl-bg: #111111;
    --cl-sidebar-bg: #0A0A0B;
    --cl-card-bg: #1A1A1C;
    --cl-card-border: rgba(255, 255, 255, 0.07);
    --cl-red-sig: #C8322B;
    --cl-red-dot: #E5483F;
    --cl-lime-accent: #A3F05C;
    --cl-text-head: #FFFFFF;
    --cl-text-body: #FFFFFF;
    --cl-text-muted: #A6A6AD;
}

/* System Font Stack & Canvas Background */
html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--cl-bg) !important;
    font-family: Inter, "Segoe UI", system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif !important;
    color: var(--cl-text-body) !important;
}

[data-testid="stHeader"] {
    background: transparent !important;
}

/* Main Content Padding & Spacing */
.main .block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 3rem !important;
    max-width: 1400px;
}

/* Sidebar Restyling */
section[data-testid="stSidebar"], div[data-testid="stSidebar"] {
    background-color: var(--cl-sidebar-bg) !important;
    border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
}

section[data-testid="stSidebar"] .block-container,
div[data-testid="stSidebar"] .block-container {
    padding-top: 2rem !important;
}

/* Sidebar Radio Navigation List */
div[data-testid="stSidebar"] div[role="radiogroup"] > label,
section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 10px 14px !important;
    border-radius: 12px !important;
    margin-bottom: 6px !important;
    transition: background 0.2s ease !important;
    border-left: 4px solid transparent !important;
}

div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background: rgba(255, 255, 255, 0.04) !important;
}

div[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked),
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background: rgba(200, 50, 43, 0.18) !important;
    border-left: 4px solid var(--cl-lime-accent) !important;
    border-radius: 4px 12px 12px 4px !important;
}

div[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

/* Selected radio dot color */
div[data-testid="stSidebar"] div[role="radiogroup"] label div[role="radio"][aria-checked="true"] > div,
section[data-testid="stSidebar"] div[role="radiogroup"] label div[role="radio"][aria-checked="true"] > div {
    background-color: var(--cl-red-dot) !important;
    border-color: var(--cl-red-dot) !important;
}

/* Custom Card Container (st.container(border=True)) */
div[data-testid="stVerticalBlockBorderWrapper"] {
    margin-bottom: 1.5rem !important;
}

div[data-testid="stVerticalBlockBorderWrapper"] > div {
    background-color: var(--cl-card-bg) !important;
    border: 1px solid var(--cl-card-border) !important;
    border-radius: 20px !important;
    box-shadow: 0 14px 34px rgba(0, 0, 0, 0.45) !important;
    padding: 24px !important;
}

/* Buttons - Primary & Secondary Pill Styling */
button[kind="primary"], [data-testid="stBaseButton-primary"] {
    background-color: var(--cl-red-sig) !important;
    color: #FFFFFF !important;
    border-radius: 9999px !important;
    border: none !important;
    font-weight: 500 !important;
    box-shadow: 0 4px 14px rgba(200, 50, 43, 0.35) !important;
    transition: transform 0.15s ease, background-color 0.15s ease !important;
}

button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover {
    background-color: #D63932 !important;
    transform: translateY(-1px);
}

button[kind="secondary"], [data-testid="stBaseButton-secondary"] {
    border-radius: 9999px !important;
    background-color: transparent !important;
    border: 1px solid rgba(255, 255, 255, 0.18) !important;
    color: #FFFFFF !important;
    transition: background-color 0.15s ease !important;
}

button[kind="secondary"]:hover, [data-testid="stBaseButton-secondary"]:hover {
    background-color: rgba(255, 255, 255, 0.08) !important;
}

/* Form Inputs, Selectboxes, Textareas */
input[type="text"], input[type="password"], input[type="number"], textarea {
    border-radius: 14px !important;
    background-color: #232326 !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    color: #FFFFFF !important;
}

input:focus, textarea:focus {
    border-color: var(--cl-red-sig) !important;
    box-shadow: 0 0 0 1px var(--cl-red-sig) !important;
}

div[data-baseweb="select"] > div {
    border-radius: 14px !important;
    background-color: #232326 !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
}

/* Expanders */
div[data-testid="stExpander"] {
    background-color: var(--cl-card-bg) !important;
    border: 1px solid var(--cl-card-border) !important;
    border-radius: 16px !important;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.35) !important;
    margin-bottom: 1rem !important;
}

/* Alerts Restyling */
div[data-testid="stAlert"] {
    border-radius: 16px !important;
    border: none !important;
}

/* Monospace Code Chips */
code {
    border-radius: 8px !important;
    padding: 2px 6px !important;
}

/* Hero Banner Layout */
.cl-hero-banner {
    position: relative;
    background-color: var(--cl-red-sig);
    border-radius: 28px;
    box-shadow: 0 14px 34px rgba(0, 0, 0, 0.45);
    overflow: hidden;
    margin-bottom: 2rem;
    width: 100%;
    box-sizing: border-box;
    display: flex;
    flex-direction: row;
    align-items: center;
}

.cl-hero-banner-large {
    min-height: 360px !important;
}

.cl-hero-banner-standard {
    min-height: 240px !important;
}

.cl-hero-content {
    position: relative;
    z-index: 2;
    padding: 36px 40px;
    width: 55%;
    max-width: 55%;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.cl-hero-title {
    font-size: 46px !important;
    font-weight: 500 !important;
    letter-spacing: -0.02em !important;
    line-height: 1.15 !important;
    color: #FFFFFF !important;
    margin: 0 0 14px 0 !important;
}

.cl-hero-intro {
    font-size: 16px !important;
    line-height: 1.5 !important;
    color: rgba(255, 255, 255, 0.92) !important;
    margin: 0 !important;
}

.cl-hero-artwork-frame {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    width: 50%;
    height: 100%;
    overflow: hidden;
    display: flex;
    justify-content: flex-end;
    align-items: flex-end;
    pointer-events: none;
    z-index: 1;
}

.cl-hero-artwork {
    height: 100%;
    width: 100%;
    object-fit: cover;
    object-position: right bottom;
    mask-image: linear-gradient(to right, transparent 0%, black 80px);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, black 80px);
}

@media (max-width: 900px) {
    .cl-hero-artwork-frame {
        display: none !important;
    }
    .cl-hero-content {
        width: 100% !important;
        max-width: 100% !important;
        padding: 24px 20px !important;
    }
    .cl-hero-banner {
        min-height: auto !important;
    }
    .cl-hero-title {
        font-size: 30px !important;
    }
}

/* Sentinel Rail Frame Container */
.cl-sentinel-frame {
    border-radius: 22px;
    overflow: hidden;
    box-shadow: 0 14px 34px rgba(0, 0, 0, 0.45);
    border: 1px solid rgba(255, 255, 255, 0.07);
    margin-bottom: 24px;
    background-color: var(--cl-card-bg);
}

.cl-sentinel-img {
    width: 100%;
    height: auto;
    display: block;
    border-radius: 22px;
}
</style>"""


def apply_theme() -> None:
    """Inject the unified visual design CSS into the current Streamlit session."""
    st.html(CL_THEME_CSS)


def hero(title: str, intro: str | None = None, is_large: bool = False) -> None:
    """Render the standard or large hero banner with red container and right artwork."""
    hero_class = "cl-hero-banner-large" if is_large else "cl-hero-banner-standard"
    title_escaped = html.escape(title)
    intro_html = f'<p class="cl-hero-intro">{html.escape(intro)}</p>' if intro else ""

    artwork_data_uri = _load_asset_base64("hero_artwork.png")
    artwork_html = ""
    if artwork_data_uri:
        artwork_html = (
            f'<div class="cl-hero-artwork-frame">'
            f'<img src="{artwork_data_uri}" alt="CIPHER-LENS" class="cl-hero-artwork" />'
            f'</div>'
        )

    hero_html = (
        f'<div class="cl-hero-banner {hero_class}">'
        f'<div class="cl-hero-content">'
        f'<h1 class="cl-hero-title">{title_escaped}</h1>'
        f'{intro_html}'
        f'</div>'
        f'{artwork_html}'
        f'</div>'
    )
    st.html(hero_html)


def render_sentinel_rail() -> None:
    """Render the two stacked sentinel frames on Pages 1 and 2."""
    s1_uri = _load_asset_base64("sentinel_01.png")
    s2_uri = _load_asset_base64("sentinel_02.png")

    frames = []
    if s1_uri:
        frames.append(
            f'<div class="cl-sentinel-frame"><img src="{s1_uri}" alt="Sentinel 01" class="cl-sentinel-img" /></div>'
        )
    if s2_uri:
        frames.append(
            f'<div class="cl-sentinel-frame"><img src="{s2_uri}" alt="Sentinel 02" class="cl-sentinel-img" /></div>'
        )
    if frames:
        st.html("".join(frames))
