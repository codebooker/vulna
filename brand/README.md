# Vulna Brand Assets

Canonical logo and mark files for the Vulna project. Use these instead of
re-exporting or recoloring ad hoc.

| File | Use |
|---|---|
| `vulna-logo.svg` | Full lockup (mark + wordmark), scalable master |
| `vulna-logo.png` | Full lockup, raster — README, docs, slides |
| `vulna-mark.svg` | Shield mark only, scalable — app header, favicons, avatars |
| `vulna-mark.png` | Shield mark only, raster (transparent background) |

## Color palette

| Swatch | Hex | Role |
|---|---|---|
| Deep teal | `#013B3B` | Shield left half, dark accents |
| Teal | `#008080` | Shield right half |
| Brand teal | `#006666` | Wordmark, primary brand color |
| Bright teal | `#00A3A3` | Pixel-dissolve accents, highlights |
| White | `#FFFFFF` | V mark (left face) |
| Mist | `#C6D2CF` | V mark (right face, on raster) |

## Wordmark

The master lockup sets the "Vulna" wordmark in a geometric sans at weight 500
with `-1` letter-spacing. Raster exports in this folder bake **Poppins Medium**,
which closely matches the master. When editing the SVG, keep the wordmark on the
`#006666` brand teal.

## Regenerating raster exports

```bash
# From the repository root (requires cairosvg: pip install cairosvg)
python3 -c "import cairosvg; cairosvg.svg2png(url='brand/vulna-mark.svg', write_to='brand/vulna-mark.png', output_width=512, output_height=483)"
```

The full-lockup `vulna-logo.png` is the designer's original high-resolution
export and should be replaced from source rather than re-rendered.
